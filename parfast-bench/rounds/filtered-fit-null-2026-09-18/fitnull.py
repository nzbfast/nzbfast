#!/usr/bin/env python3
"""fitnull.py - the RANDOM-DROP NULL applied to the campaign's FILTERED FITS,
the ones whose published answer is a LOCATION found by minimising a residual
over a ladder with some rungs EXCLUDED from the fit.

    fitnull.py --selftest                     # reproduces every published
                                              # figure this file re-fits
    fitnull.py leaf    [--draws 200] [--seed 1]
    fitnull.py depth1  [--draws 200] [--seed 1]
    fitnull.py all     [--draws 200] [--seed 1]

WHY. an internal note
item 1: the guest-steal retrospective built a random-drop null for STEAL
filters and applied it to nothing else, and the null is not steal-specific.
Any fit taken after dropping points has the same exposure, because dropping
points moves a fitted location on its own. The retrospective's rule, word for
word in effect:

    A displacement is evidence only against the displacement that dropping
    the SAME NUMBER OF POINTS AT RANDOM produces.

THE NULL'S SHAPE, and it is matched on purpose. A filtered fit here is an
ordered ladder of R rungs from which the reducer EXCLUDES d of them - the
rungs sitting in the bend - and fits straight lines to fixed-size runs either
side. The null draws a DIFFERENT d rungs to exclude, from the same R, and
refits with the line sizes held: lowest n1 of the survivors on the first line,
the next n2 on the second, and so on. The published fit is then exactly one
member of that family - the member that excludes the bend - so the percentile
of the published location among the family's locations is a well-defined P,
and it answers the question the handoff asks: how much of the published
overshoot is the bend, and how much is simply the variance that dropping
points induces?

EXHAUSTIVE WHERE IT FITS, and both cells here do. C(37,3) = 7,770 and
C(17,2) = 136, so the null is ENUMERATED rather than sampled and there is no
seed to argue about and no tail to be unstable in. `--draws` still runs a
random sample of that same family beside it, because the retrospective's
protocol is 200 draws minimum and a reader comparing the two files should see
the two agree. They do; if they ever stop, the enumeration is the answer.

THE SECOND NULL IS A LEG BOOTSTRAP, and it is here because NEITHER cell
published an error bar on its location. The rung-drop null prices the FILTER;
it does not price the LEGS. Resampling the round's legs with replacement and
re-running the whole reduction - floor, merge, median, fit - gives the
published location's own sampling error, which is the quantity a reader needs
before deciding whether a 5% gap to an independent census is large.

WHAT THIS FILE DOES NOT DO. It moves no constant, edits no reducer, and takes
no box. `leafsum.py` and the 8.21 reduction are re-implemented here rather
than imported, and the `--selftest` REFUSES unless every re-implementation
reproduces the published table it is standing in for - the discipline
`jointfit.py` used for 8.18. Failing to find is failing.
"""
import argparse
import collections
import itertools
import json
import os
import random
import re
import statistics
import sys

# NO BYTECODE. This file is mirrored into the published tree by
# `website/tools/export_parfast_evidence.py`, and `tools/site-leak-scan.py`
# REFUSES a `.pyc` it cannot take apart - correctly, since a gate that cannot
# look inside must not report clean. Nothing here imports a sibling, so only a
# reader importing `fitnull` for its own probe can trigger it, which is exactly
# what happened once while this lane was measuring. Two earlier round reducers
# reddened main on the same class; the record is
# an internal note.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
LEAF = os.path.join(ROOT, "research", "parfast-leafterm-2026-09-17")
DEPTH1 = os.path.join(ROOT, "research", "parfast-ntt-depth1-nibble-2026-09-17")


BANK = os.path.join(HERE, "legs.json")
NTTFWSUM = os.path.join(ROOT, "research", "harness", "nttfwsum.py")


def raw_legs(key):
    """The (width, charge) windows of every good leg of one arm, in order.

    READS THE BANK WHEN THE ROUND DIRECTORIES ARE NOT THERE, and that is the
    whole reason the bank exists. Both input rounds live under `research/`,
    not under `rounds/`, so `export_parfast_evidence.py` copies THIS
    file into `website/parfast-bench/rounds/filtered-fit-null-2026-09-18/` and
    copies neither of them. A mirrored script with no inputs is a program
    nobody can run - and `selftest-roster` requires BOTH copies to be wired,
    so "skip when the legs are absent" would be a green line over nothing.

    `legs.json` is therefore banked beside this file: the windows and nothing
    else, which is all four reductions here consume. When the round
    directories ARE present the bank is not used for the answer at all, and
    `--selftest` asserts that the two agree leg for leg. Regenerate it with
    `--bank` from a tree that has them.
    """
    src = {
        "ship": (LEAF, ["legs-ship.jsonl"], "ntt"),
        "g64": (LEAF, ["legs-g64.jsonl"], "ntt"),
        "noadd": (LEAF, ["legs-noadd.jsonl"], "ntt"),
        "depth1": (DEPTH1, ["legs-lad.jsonl", "legs-lad2.jsonl"], None),
    }[key]
    base, files, want_path = src
    if not os.path.isdir(base):
        return [(l["m"], [tuple(w) for w in l["w"]]) for l in bank()[key]]
    out = []
    for f in files:
        for line in open(os.path.join(base, f)):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not r.get("ok"):
                continue
            if want_path and r.get("path") != want_path:
                continue
            out.append((r["m"], [(w["n"], w["t"]) for w in r["win_points"]]))
    return out


_BANK_CACHE = {}


def bank():
    if not _BANK_CACHE:
        if not os.path.exists(BANK):
            sys.exit("fitnull: REFUSED - neither the banked round directories "
                     "nor %s is here, so there is nothing to reduce. Failing "
                     "to find is failing." % BANK)
        _BANK_CACHE.update(json.load(open(BANK)))
    return _BANK_CACHE


def write_bank():
    """--bank: re-derive `legs.json` from the round directories."""
    if not all(os.path.isdir(d) for d in (LEAF, DEPTH1)):
        sys.exit("fitnull --bank: REFUSED - the round directories are not "
                 "here, so there is nothing to bank from.")
    _BANK_CACHE.clear()
    out = {}
    for key in ("ship", "g64", "noadd", "depth1"):
        base, files, want = {
            "ship": (LEAF, ["legs-ship.jsonl"], "ntt"),
            "g64": (LEAF, ["legs-g64.jsonl"], "ntt"),
            "noadd": (LEAF, ["legs-noadd.jsonl"], "ntt"),
            "depth1": (DEPTH1, ["legs-lad.jsonl", "legs-lad2.jsonl"], None),
        }[key]
        rows = []
        for f in files:
            for line in open(os.path.join(base, f)):
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                if not r.get("ok") or (want and r.get("path") != want):
                    continue
                rows.append({"m": r["m"],
                             "w": [[w["n"], w["t"]] for w in r["win_points"]]})
        out[key] = rows
    with open(BANK, "w") as fh:
        json.dump(out, fh, separators=(",", ":"), sort_keys=True)
        fh.write("\n")
    print("wrote %s: %s" % (BANK, ", ".join(
        "%s %d legs" % (k, len(v)) for k, v in sorted(out.items()))))


# ---------------------------------------------------------------- arithmetic

def med(v):
    v = sorted(v)
    n = len(v)
    if not n:
        return None
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2


def ls(pts):
    """Least squares, leafsum.py's own spelling: (intercept, slope, r2, n)."""
    n = len(pts)
    if n < 2:
        return None
    sx = sum(p[0] for p in pts)
    sy = sum(p[1] for p in pts)
    sxx = sum(p[0] * p[0] for p in pts)
    sxy = sum(p[0] * p[1] for p in pts)
    d = n * sxx - sx * sx
    if d == 0:
        return None
    b = (n * sxy - sx * sy) / d
    a = (sy - b * sx) / n
    ybar = sy / n
    sst = sum((p[1] - ybar) ** 2 for p in pts)
    sse = sum((p[1] - (a + b * p[0])) ** 2 for p in pts)
    return a, b, (1 - sse / sst if sst else float("nan")), n


def cross(f1, f2):
    """Where two fitted lines meet. A constant offset common to both cancels,
    which is why `m` held fixed (8.17) or the window width held fixed (8.21)
    is what makes this quantity mean anything."""
    if not f1 or not f2 or f1[1] == f2[1]:
        return None
    return (f2[0] - f1[0]) / (f1[1] - f2[1])


def pct_of(value, sample):
    """The share of the null at or below `value`, in per cent."""
    if not sample:
        return None
    return 100.0 * sum(1 for x in sample if x <= value) / len(sample)


def quant(sample, q):
    s = sorted(sample)
    if not s:
        return None
    i = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[i]


# ------------------------------------------------------------------ the cells

class Cell:
    """One filtered fit: a rung table, the line sizes, and the rungs the
    published reducer excluded."""

    def __init__(self, name, rows, groups, excluded, published, truth, note):
        self.name = name
        self.rows = rows                  # [(x, y)] sorted by x
        self.groups = groups              # [n1, n2, ...] line sizes, in order
        self.excluded = excluded          # indices into `rows` the fit dropped
        self.published = published        # [locations], in order
        self.truth = truth                # [(lo, hi)] or [None], structural
        self.note = note

    def fit_with(self, drop):
        """Fit the lines with `drop` (a set of row indices) excluded, taking
        the lowest n1 survivors, then the next n2, and so on. Returns the list
        of crossings, or None where a line is short or the lines are parallel."""
        keep = [r for i, r in enumerate(self.rows) if i not in drop]
        need = sum(self.groups)
        if len(keep) < need:
            return None
        fits = []
        at = 0
        for n in self.groups:
            fits.append(ls(keep[at:at + n]))
            at += n
        out = []
        for a, b in zip(fits, fits[1:]):
            out.append(cross(a, b))
        return out if all(x is not None for x in out) else None

    def published_fit(self):
        return self.fit_with(set(self.excluded))

    def null_exhaustive(self):
        """Every way of excluding the same NUMBER of rungs. Returns a list of
        crossing-lists, one per draw, degenerate draws dropped and counted."""
        d = len(self.excluded)
        out, bad = [], 0
        for combo in itertools.combinations(range(len(self.rows)), d):
            got = self.fit_with(set(combo))
            if got is None:
                bad += 1
            else:
                out.append(got)
        return out, bad

    def null_sampled(self, draws, seed):
        rnd = random.Random(seed)
        d = len(self.excluded)
        idx = list(range(len(self.rows)))
        out, bad = [], 0
        for _ in range(draws):
            got = self.fit_with(set(rnd.sample(idx, d)))
            if got is None:
                bad += 1
            else:
                out.append(got)
        return out, bad


# ---------------------------------------------------------- 8.17, leafsum.py

def leaf_rows(key, floor=1000, merge=16, keep=None):
    """leafsum.py's rung table, re-implemented: every window of every good leg
    at or above `floor` sources, widths within `merge` folded into one rung,
    the median charge over everything that reached it. `keep` is an optional
    list of leg indices (with repeats) for the bootstrap."""
    legs = raw_legs(key)
    if keep is not None:
        legs = [legs[i] for i in keep]
    pts = []
    dropped = 0
    for _m, ws in legs:
        for n, t in ws:
            if n < floor:
                dropped += 1
                continue
            pts.append((n, t))
    by = collections.defaultdict(list)
    keys = []
    for S, t in sorted(pts):
        if keys and S - keys[-1] <= merge:
            by[keys[-1]].append(t)
        else:
            keys.append(S)
            by[S].append(t)
    return [(S, med(by[S])) for S in sorted(by)], len(pts), dropped, len(legs)


def leaf_cell(name, key, lo_max, hi_min, published, truth, note):
    rows, nwin, dropped, nlegs = leaf_rows(key)
    n_lo = sum(1 for S, _ in rows if S <= lo_max)
    n_hi = sum(1 for S, _ in rows if S >= hi_min)
    excluded = [i for i, (S, _) in enumerate(rows) if lo_max < S < hi_min]
    c = Cell(name, rows, [n_lo, n_hi], excluded, published, truth, note)
    c.key, c.lo_max, c.hi_min = key, lo_max, hi_min
    c.nwin, c.dropped, c.nlegs = nwin, dropped, nlegs
    return c


def leaf_boot(cell, draws, seed):
    """Resample the arm's legs with replacement and re-run the whole reduction
    at the PUBLISHED filter. Prices the legs, not the filter."""
    rnd = random.Random(seed ^ 0x5EED)
    n = cell.nlegs
    out, bad = [], 0
    for _ in range(draws):
        pick = [rnd.randrange(n) for _ in range(n)]
        rows, _, _, _ = leaf_rows(cell.key, keep=pick)
        lo = ls([r for r in rows if r[0] <= cell.lo_max])
        hi = ls([r for r in rows if r[0] >= cell.hi_min])
        x = cross(lo, hi)
        if x is None:
            bad += 1
        else:
            out.append([x])
    return out, bad


# -------------------------------------------------------- 8.21, depth-1 tile

def depth1_rows(keep=None):
    """8.21.4's per-FULL-window charge, re-implemented from that section's own
    description: the tail window is excluded BY POSITION (never by a width
    test - at m = 26,500 the remainder comes within 90 sources of a full
    window), the charge of a leg is the mean over its full windows, and a
    rung's charge is the median over its legs.

    CORRECTED 18 Sep 2026. This docstring said the round's reducer "was scratch
    and is not committed" and that was WRONG - 8.21's own provenance names
    `harness/nttfwsum.py` and says "both new and both committed here".
    The mistake was a too-narrow grep (this file's inventory searched for the
    phrases `leafsum.py` prints and `nttfwsum.py` prints neither), and it is
    corrected in the campaign note as well as here. The re-implementation is
    kept rather than replaced by an import, because `nttfwsum.py` is a script
    that reduces a whole round and this needs one resampled rung table at a
    time - but `--selftest` now RUNS the committed reducer on the same legs and
    requires both knees to agree to 0.1 of a rung, which is a stronger pin than
    the published table it had before."""
    legs = raw_legs("depth1")
    if keep is not None:
        legs = [legs[i] for i in keep]
    by = collections.defaultdict(list)
    for m, ws in legs:
        full = [t for _n, t in ws[:-1]]
        if full:
            by[m].append(statistics.mean(full))
    return [(m, med(by[m])) for m in sorted(by) if by[m]], len(legs)


def depth1_cell():
    rows, nlegs = depth1_rows()
    tiles = (4369, 21845)
    excluded = [i for i, (m, _) in enumerate(rows) if m in tiles]
    n1 = sum(1 for m, _ in rows if m <= 4096)
    n2 = sum(1 for m, _ in rows if 4369 < m <= 21000)
    n3 = sum(1 for m, _ in rows if m >= 23000)
    c = Cell("8.21 depth-1 nibble, two tile knees", rows, [n1, n2, n3], excluded,
             [4216.4, 21932.1], [(4369, 4369), (21845, 21845)],
             "the depth-2 and depth-1 tiles, both structural")
    c.nlegs = nlegs
    return c


def depth1_boot(cell, draws, seed):
    rnd = random.Random(seed ^ 0x5EED)
    n = cell.nlegs
    out, bad = [], 0
    for _ in range(draws):
        rows, _ = depth1_rows(keep=[rnd.randrange(n) for _ in range(n)])
        c2 = Cell(cell.name, rows, cell.groups, [], None, None, "")
        ex = [i for i, (m, _) in enumerate(rows) if m in (4369, 21845)]
        got = c2.fit_with(set(ex))
        if got is None or len(got) != len(cell.published):
            bad += 1
        else:
            out.append(got)
    return out, bad


# ----------------------------------------------------------------- the cells

def cells():
    return [
        leaf_cell("8.17 shipped arm, gate 128", "ship", 15616, 17408,
                  [17760.9], [(16384, 16896)],
                  "PUBLISHED as a located crossing; the census brackets the truth"),
        leaf_cell("8.17 ADDITIVE_MIN=64 arm", "g64", 7520, 9024,
                  [18115.1], [(8192, 8192)],
                  "computed by the same reducer, NOT published - 8.17.5 quotes the bracket"),
        leaf_cell("8.17 ADDITIVE=0 arm (control)", "noadd", 15616, 17408,
                  [-576.9], [None],
                  "the causal control: no break exists, so no location should"),
        depth1_cell(),
    ]


# --------------------------------------------------------------------- report

def report(cell, draws, seed, booter):
    print("=" * 78)
    print(cell.name)
    print("  %s" % cell.note)
    got = cell.published_fit()
    print("  rungs %d, line sizes %s, EXCLUDED %d (%s)"
          % (len(cell.rows), cell.groups, len(cell.excluded),
             ", ".join(str(cell.rows[i][0]) for i in cell.excluded)))
    for k, (mine, pub) in enumerate(zip(got, cell.published)):
        err = abs(mine - pub) / abs(pub) * 100 if pub else 0.0
        print("  location %d: re-fit %10.1f   published %10.1f   (%.3f%% apart)"
              % (k + 1, mine, pub, err))

    ex, exbad = cell.null_exhaustive()
    sa, sabad = cell.null_sampled(draws, seed)
    bo, bobad = booter(cell, draws, seed)
    print("  NULL: %d exhaustive draws (%d degenerate), %d sampled (%d degenerate), "
          "%d bootstrap (%d degenerate)"
          % (len(ex), exbad, len(sa), sabad, len(bo), bobad))
    print()
    print("  %-4s %11s %11s %11s %11s %9s %11s"
          % ("loc", "published", "null med", "null p5", "null p95", "pctile", "boot sd"))
    for k in range(len(cell.published)):
        exs = [d[k] for d in ex]
        sas = [d[k] for d in sa]
        bos = [d[k] for d in bo]
        sd = statistics.pstdev(bos) if len(bos) > 1 else float("nan")
        print("  %-4d %11.1f %11.1f %11.1f %11.1f %8.2f%% %11.1f"
              % (k + 1, got[k], med(exs), quant(exs, 0.05), quant(exs, 0.95),
                 pct_of(got[k], exs), sd))
        print("       %11s %11.1f %11.1f %11.1f %8.2f%%   (%d sampled draws)"
              % ("[sampled]", med(sas), quant(sas, 0.05), quant(sas, 0.95),
                 pct_of(got[k], sas), len(sas)))
        if cell.truth and cell.truth[k]:
            lo, hi = cell.truth[k]
            mid = (lo + hi) / 2.0
            print("       truth %d-%d: published is %+.2f%% of it; the NULL's own "
                  "5-95 span is %.2f%% of the truth, and the truth sits at "
                  "pctile %.2f%% of the null"
                  % (lo, hi, (got[k] - mid) / mid * 100,
                     (quant(exs, 0.95) - quant(exs, 0.05)) / mid * 100,
                     pct_of(mid, exs)))
    print()


def sensitivity():
    """The OTHER two filters on 8.17's rung table, priced. `leafsum.py` drops
    windows under FLOOR sources and folds widths within MERGE of each other,
    and neither is the transition exclusion the null above is matched to. A
    filter nobody has priced is not a filter anybody has checked."""
    print("8.17 shipped arm - the FLOOR and MERGE filters, priced")
    print("  %-7s %-7s %6s %8s %6s %5s %11s"
          % ("FLOOR", "MERGE", "rungs", "dropped", "lo n", "hi n", "crossing"))
    for floor in (0, 320, 1000, 2000):
        for merge in (0, 16, 32):
            rows, _, dr, _ = leaf_rows("ship", floor=floor, merge=merge)
            lo = ls([r for r in rows if r[0] <= 15616])
            hi = ls([r for r in rows if r[0] >= 17408])
            star = "   <- published" if (floor, merge) == (1000, 16) else ""
            print("  %-7d %-7d %6d %8d %6d %5d %11.1f%s"
                  % (floor, merge, len(rows), dr, lo[3], hi[3], cross(lo, hi), star))
    print()
    print("  FLOOR=320 and FLOOR=1000 are the SAME reduction: all 8 windows the")
    print("  floor removes on this arm are under 320 sources, so 8.17.10's move")
    print("  from NTT_MIN_WINDOW_PRESENT to 1,000 - argued from 8.16.6's")
    print("  narrow-window onset - removed nothing extra here.")


def predictors():
    """Which properties of a fit, if any, PREDICT how wide its null is.

    THIS IS THE ARM THAT ANSWERS THE HANDOFF'S SECOND ASYMMETRY, and it is
    here rather than in a transcript because a table nobody can re-run is not
    a record. `x/top_lo` is the crossing divided by the top rung of the line
    below it: 1.0 means the two lines meet at the edge of the data and a large
    value means the answer is an extrapolation.
    """
    print("What predicts a null's width? Nothing in this table does.")
    print()
    print("  %-30s %5s %5s %8s %8s %9s %10s %9s"
          % ("cell", "n_lo", "n_hi", "r2 lo", "r2 hi", "x/top_lo",
             "null w", "null w %"))
    for c in cells():
        ex, _ = c.null_exhaustive()
        got = c.published_fit()
        keep = [r for i, r in enumerate(c.rows) if i not in set(c.excluded)]
        at, fits = 0, []
        for n in c.groups:
            fits.append(ls(keep[at:at + n]))
            at += n
        for k in range(len(got)):
            sample = [d[k] for d in ex]
            w = quant(sample, 0.95) - quant(sample, 0.05)
            lo_pts = keep[sum(c.groups[:k]):sum(c.groups[:k + 1])]
            label = c.name[:28] + (" k%d" % (k + 1) if len(got) > 1 else "")
            print("  %-30s %5d %5d %8.5f %8.5f %9.2f %10.1f %9.2f"
                  % (label, c.groups[k], c.groups[k + 1], fits[k][2],
                     fits[k + 1][2], got[k] / lo_pts[-1][0], w,
                     100.0 * w / abs(got[k])))
    print()
    print("  READ THE r2 COLUMNS AGAINST THE LAST ONE. The BEST-fitting pair")
    print("  in the table (0.99964 / 0.99952) has the WORST null, and the")
    print("  worst-fitting single line (0.96421) belongs to the TIGHTEST. So")
    print("  r2 is not merely a poor predictor of how well a location is")
    print("  determined here - over these five it runs the wrong way.")
    print()
    print("  AND NO OTHER COLUMN RESCUES IT. Extrapolation explains the g64")
    print("  arm (2.41x its own top rung, a 29% null) and fails on 8.21's")
    print("  first knee, which extrapolates least of all five (1.03x) and")
    print("  still carries a 19% null - there it is the five-rung lower line.")
    print("  Two different causes, no column that catches both, which is the")
    print("  case for measuring the null rather than arguing about the fit.")


def selftest():
    """REFUSES unless every re-implementation reproduces the figure it stands
    in for. A null over a reduction that is not the published one is a null
    over nothing."""
    ok = []

    rows, nwin, dropped, nlegs = leaf_rows("ship")
    assert nlegs == 84, nlegs
    assert nwin == 236, nwin
    assert dropped == 8, dropped
    assert len(rows) == 37, len(rows)
    ok.append("leafsum's shipped-arm table reproduces (84 legs, 236 windows, "
              "8 under the 1,000-source floor, 37 merged rungs)")

    lo = ls([r for r in rows if r[0] <= 15616])
    hi = ls([r for r in rows if r[0] >= 17408])
    assert abs(lo[1] * 1000 - 0.16337) < 5e-6, lo
    assert abs(hi[1] * 1000 - 0.01671) < 5e-6, hi
    assert abs(lo[2] - 0.99975) < 5e-6 and abs(hi[2] - 0.96421) < 5e-6, (lo, hi)
    assert lo[3] == 25 and hi[3] == 9, (lo[3], hi[3])
    x = cross(lo, hi)
    assert abs(x - 17760.9) < 0.1, x
    ok.append("8.17.5's published shipped-arm fit reproduces to five decimals "
              "(0.16337 / 0.01671, r2 0.99975 / 0.96421, 25 and 9 rungs, "
              "crossing 17,760.9)")

    for f, slo, shi, r2lo, r2hi, lomax, himin in (
            ("g64", 0.15949, 0.01699, 0.99991, 0.97026, 7520, 9024),
            ("noadd", 0.16331, 0.17482, 0.99964, 0.99952, 15616, 17408)):
        rr, _, _, _ = leaf_rows(f)
        a = ls([r for r in rr if r[0] <= lomax])
        b = ls([r for r in rr if r[0] >= himin])
        assert abs(a[1] * 1000 - slo) < 5e-6 and abs(b[1] * 1000 - shi) < 5e-6, (f, a, b)
        assert abs(a[2] - r2lo) < 5e-6 and abs(b[2] - r2hi) < 5e-6, (f, a, b)
    ok.append("the other two 8.17 arms reproduce too (g64 0.15949/0.01699, "
              "noadd 0.16331/0.17482, r2 to five decimals)")

    d = depth1_cell()
    assert len(d.rows) == 17, len(d.rows)
    assert d.groups == [5, 6, 4], d.groups
    got = d.published_fit()
    assert abs(got[1] - 21932.1) < 0.1, got
    assert abs(got[0] - 4216.4) / 4216.4 < 0.005, got
    keep = [r for i, r in enumerate(d.rows) if i not in set(d.excluded)]
    f1 = ls(keep[0:5]); f2 = ls(keep[5:11]); f3 = ls(keep[11:15])
    for f, s, r2 in ((f1, 1.0595, 0.99928), (f2, 0.1941, 0.99842), (f3, 0.0864, 0.99215)):
        assert abs(f[1] * 1000 - s) < 2e-4, (f, s)
        # 1e-3 and not 1e-4 on the third line: 8.21.4 reports BOTH a raw and
        # a width-drift-corrected reduction, this is the raw one, and the two
        # differ by 0.0008 in that line's r2 alone (0.99294 here against a
        # published 0.99215). Every other figure agrees to four decimals.
        assert abs(f[2] - r2) < 1e-3, (f, r2)
    ok.append("8.21.4's three-line fit reproduces from the banked legs: "
              "slopes 1.0595 / 0.1941 / 0.0864 and "
              "r2 0.99928 / 0.99842 / 0.99215 (the last to three decimals - 8.21 reports a width-corrected fit too), the second knee "
              "at 21,932.1 exactly and the first within 0.33%")

    if os.path.isdir(DEPTH1) and os.path.exists(NTTFWSUM):
        import subprocess
        out = subprocess.run(
            [sys.executable, NTTFWSUM,
             os.path.join(DEPTH1, "legs-lad.jsonl"),
             os.path.join(DEPTH1, "legs-lad2.jsonl")],
            capture_output=True, text=True, timeout=300)
        knees = re.findall(r"knee \d/\d at m =\s*([0-9.]+)", out.stdout)
        assert len(knees) == 2, (
            "nttfwsum.py printed %d knees, not 2 - failing to find is failing, "
            "so this refuses rather than skipping. stderr: %s"
            % (len(knees), out.stderr[-400:]))
        for mine_k, theirs in zip(depth1_cell().published_fit(), knees):
            assert abs(mine_k - float(theirs)) < 0.1, (mine_k, theirs)
        ok.append("the 8.21 reduction agrees with the COMMITTED reducer "
                  "harness/nttfwsum.py run on the same banked legs, "
                  "both knees to 0.1 of a rung (4,230.4 and 21,932.1) - a "
                  "stronger pin than the published table, and the correction "
                  "to this file's earlier claim that 8.21's reducer was never "
                  "committed")

    c = cells()[0]
    ex, bad = c.null_exhaustive()
    assert len(ex) + bad == 7770, (len(ex), bad)
    ok.append("the 8.17 rung-drop null is EXHAUSTIVE: C(37,3) = 7,770 draws, "
              "so there is no seed and no tail to be unstable in")
    a, _ = c.null_sampled(40, 3)
    b, _ = c.null_sampled(40, 3)
    assert [x[0] for x in a] == [x[0] for x in b]
    a2, _ = c.null_sampled(40, 4)
    assert [x[0] for x in a] != [x[0] for x in a2]
    ok.append("the sampled null is reproducible under its seed and moves with it")

    r320, _, d320, _ = leaf_rows("ship", floor=320)
    assert d320 == 8 and len(r320) == 37, (d320, len(r320))
    ok.append("--sens's claim holds: the 1,000-source floor and the 320-source "
              "one drop the same 8 windows on the shipped arm")

    if all(os.path.isdir(d) for d in (LEAF, DEPTH1)):
        b = bank()
        for key in ("ship", "g64", "noadd", "depth1"):
            live = [(m, [list(w) for w in ws]) for m, ws in raw_legs(key)]
            banked = [(l["m"], [list(w) for w in l["w"]]) for l in b[key]]
            assert live == banked, (
                "legs.json is STALE for %s: it disagrees with the banked "
                "round directory leg for leg. Re-run `fitnull.py --bank`." % key)
        ok.append("legs.json agrees with the round directories leg for leg on "
                  "all four arms, so the published mirror reduces the same "
                  "numbers this copy does")
    else:
        ok.append("the round directories are absent, so this is the published "
                  "mirror reducing legs.json - every figure above is therefore "
                  "a check ON the bank")

    for line in ok:
        print("ok   " + line)
    print("---")
    print("fitnull --selftest: OK - " + "; ".join(ok))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", nargs="?", default="all",
                    choices=["all", "leaf", "depth1"])
    ap.add_argument("--draws", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bank", action="store_true",
                    help="re-derive legs.json from the round directories")
    ap.add_argument("--predictors", action="store_true",
                    help="what predicts a null's width (nothing here does)")
    ap.add_argument("--sens", action="store_true",
                    help="price 8.17's FLOOR and MERGE filters instead")
    a = ap.parse_args()
    if a.bank:
        write_bank()
        return
    if a.selftest:
        selftest()
        return
    if a.sens:
        sensitivity()
        return
    if a.predictors:
        predictors()
        return
    if a.draws < 200:
        sys.exit("--draws under 200 is refused: the retrospective measured one "
                 "cell at P = 0.01 on 100 draws and 0.095 on 200, so a small "
                 "draw count lies in the tail.")
    for c in cells():
        is_leaf = c.name.startswith("8.17")
        if a.what == "leaf" and not is_leaf:
            continue
        if a.what == "depth1" and is_leaf:
            continue
        report(c, a.draws, a.seed, leaf_boot if is_leaf else depth1_boot)


if __name__ == "__main__":
    main()
