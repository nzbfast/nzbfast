#!/usr/bin/env python3
"""Screen a wcomb ladder's CROSSOVERS with BOTH firmness tests, mechanised.

A crossover is a three-digit number interpolated between two rungs, and this
campaign has published several that rest on a bracket the instrument cannot
resolve. There are two tests and only the first was ever routinely applied:

  TEST 1, the usual one: are the rungs BRACKETING the crossing present, and is
  the ladder monotone through them? (ladder-monotonicity-audit.py does the
  monotonicity half.)

  TEST 2, added by rounds/crband-2026-09-18/ and applied by hand
  there: THE BRACKETING RUNG'S OWN DISTANCE FROM `F/T = 1` MUST EXCEED THAT
  RUNG'S A/A FLOOR. If the nearest measured rung sits 1.0% from the crossing
  while its own A/A pair disagree by 3.2%, the crossing is resting on noise and
  the digits are not there. THREE OF FOUR banked unpinned readings FAIL this
  test and nobody had applied it until crband did, by hand, for four rows.

This does both, for CPU and for WALL, for every ladder in every log given. It
exists because a hand-applied test is applied to the rows somebody thought to
check - and the interesting case is the row nobody suspected.

IT IS A SCREEN, NOT A VERDICT. `INSIDE` does not mean the crossover is wrong;
it means the sitting cannot resolve it and it must not be quoted to the row.
That is a publishable answer. Do not widen the comparison to clear a rung.

USAGE  python3 bracket-firmness.py <wcomb log> [...]
Groups by (label, phase, threads) exactly as rowgate.py read and band-trade.py
do, so an interleaved ladder prints one block per pool.
"""
import math
import os
import statistics as st
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "crband-2026-09-18"))
# BEFORE the sibling import, and it is load-bearing rather than tidy. This file
# is MIRRORED into website/parfast-bench/, which ships, and loading a sibling
# module from there writes `__pycache__/band-trade.cpython-*.pyc` NEXT TO THE
# SOURCE - inside the published tree, where `site leak scan` refuses it. The
# same pairing bit w3winred.py, whose step in size-gate.yml says so at length,
# and the same class was fixed in the published tree on 18 Sep 2026
# (`6e64ecb91`). Wiring a round reducer's --selftest into CI and keeping the
# published tree clean of bytecode pull against each other; only the pair is
# green.
sys.dont_write_bytecode = True
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "band_trade",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                 "crband-2026-09-18", "band-trade.py"))
band_trade = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(band_trade)


def interp(pts):
    """Log-interpolated m where log(F/T) first turns >= 0, reading up.

    The SAME rule as rowgate.py's cross(), restated rather than imported so a
    change there is caught by the selftest below rather than silently adopted.
    Returns (m, lower_rung, upper_rung) or (None, reason, None).
    """
    for (m0, y0), (m1, y1) in zip(pts, pts[1:]):
        if y0 < 0 <= y1:
            m = math.exp(math.log(m0) + (0 - y0) / (y1 - y0) * (math.log(m1) - math.log(m0)))
            return m, m0, m1
    if pts and pts[0][1] >= 0:
        return None, "crossed BELOW the ladder's bottom rung %d" % pts[0][0], None
    if pts and pts[-1][1] < 0:
        return None, "never crossed by the top rung %d" % pts[-1][0], None
    return None, "no points", None


def main(paths):
    lad = band_trade.parse(paths)
    if not lad:
        print("REFUSED: no legs in %s" % ", ".join(paths))
        return 2
    groups = {}
    for r in lad:
        groups.setdefault((r["label"], r["phase"], r["threads"]), []).append(r)

    worst = 0
    for key in sorted(groups):
        label, phase, threads = key
        rows = groups[key]
        cells = {}
        for r in rows:
            cells.setdefault(r["m"], []).append(r)
        stats = {}
        cpupts, wallpts = [], []
        for m in sorted(cells):
            c = cells[m]
            fold = [r for r in c if r["arm"] in ("fold", "fold2")]
            force = [r for r in c if r["arm"] in ("force", "force2")]
            if not fold or not force:
                continue
            # The SAME path assert band-trade.py makes. A fold leg that took the
            # transform (or the reverse) is a mislabelled arm, and a crossover
            # built from one is meaningless - so this refuses rather than
            # screening it.
            for r in force:
                if r["path"] != "ntt":
                    sys.exit("REFUSED: force leg took the fold at m=%d in %s" % (m, label))
            for r in fold:
                if r["path"] != "fold":
                    sys.exit("REFUSED: fold leg took the transform at m=%d in %s" % (m, label))
            cF = st.median(r["cpu"] for r in fold)
            cT = st.median(r["cpu"] for r in force)
            wF = st.median(r["wall"] for r in fold)
            wT = st.median(r["wall"] for r in force)
            aacpu = max(band_trade.aa_floor(c, "cpu", "fold"),
                        band_trade.aa_floor(c, "cpu", "force")) * 100.0
            aawall = max(band_trade.aa_floor(c, "wall", "fold"),
                         band_trade.aa_floor(c, "wall", "force")) * 100.0
            stats[m] = dict(cpu=cF / cT, wall=wF / wT, aacpu=aacpu, aawall=aawall)
            cpupts.append((m, math.log(cF / cT)))
            wallpts.append((m, math.log(wF / wT)))

        print("== %s %s threads=%s   CROSSING BRACKET FIRMNESS" % (label, phase, threads))
        for metric, pts, ratio_key, floor_key in (("CPU", cpupts, "cpu", "aacpu"),
                                                  ("wall", wallpts, "wall", "aawall")):
            m, lo, hi = interp(pts)
            if m is None:
                print("   %-4s crossover: NONE - %s. Nothing to bracket; this "
                      "ladder cannot be quoted for %s." % (metric, lo, metric))
                worst = max(worst, 1)
                continue
            cells_txt = []
            bad = 0
            for rung in (lo, hi):
                sdict = stats[rung]
                dist = abs(sdict[ratio_key] - 1.0) * 100.0
                floor = sdict[floor_key]
                firm = dist > floor
                if not firm:
                    bad += 1
                cells_txt.append("%d: %.1f%% vs %.1f%% %s"
                                 % (rung, dist, floor, "firm" if firm else "**INSIDE**"))
            verdict = ("FIRM both sides" if bad == 0 else
                       "RESTS ON NOISE (%d of 2 brackets inside their own A/A floor)" % bad)
            if bad:
                worst = max(worst, 1)
            print("   %-4s crossover m ~ %.0f   | %s | %s | %s"
                  % (metric, m, cells_txt[0], cells_txt[1], verdict))
        print()
    return 0


# THE SELFTEST PINS THIS TO crband's PUBLISHED TABLE, which is the only
# independent check available: those four rows were computed BY HAND in
# rounds/crband-2026-09-18/README.md section 3, so agreeing with them
# to the decimal is evidence this reducer implements the test that round
# described rather than a near neighbour of it. It also guards the floor
# definition: band-trade.aa_floor is imported, so a change there that moved a
# floor by a tenth would show up here as a failed row rather than as a quietly
# different screen.
SELFTEST = [
    ("../crpool4m-2026-09-17/logs/crt16.log", "4mc-t16", 16, "CPU",
     "387", "384: 1.0% vs 3.2% **INSIDE**", "416: 9.2% vs 3.4% firm"),
    ("../crband-2026-09-18/logs/csolo.log", "4mcb-solo", 16, "CPU",
     "359", "352: 1.7% vs 2.0% **INSIDE**", "384: 5.9% vs 0.5% firm"),
    ("../crband-2026-09-18/logs/cinter.log", "4mcb-inter", 16, "CPU",
     "357", "352: 1.5% vs 1.8% **INSIDE**", "384: 7.2% vs 1.6% firm"),
]


def selftest():
    import io
    import contextlib
    here = os.path.dirname(os.path.abspath(__file__))
    bad = 0
    for rel, label, threads, metric, m, lob, hib in SELFTEST:
        path = os.path.join(here, rel)
        if not os.path.exists(path):
            print("SELFTEST SKIP %s - banked log absent" % rel)
            continue
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main([path])
        want_hdr = "== %s create threads=%d" % (label, threads)
        block, seen = [], False
        for ln in buf.getvalue().splitlines():
            if ln.startswith("=="):
                seen = ln.startswith(want_hdr)
            elif seen and ln.strip().startswith(metric):
                block.append(ln)
        if not block:
            print("SELFTEST FAIL %s %s - no %s row found" % (label, threads, metric))
            bad += 1
            continue
        line = block[0]
        for want in ("m ~ %s" % m, lob, hib):
            if want not in line:
                print("SELFTEST FAIL %s: expected %r in\n   %s" % (label, want, line.strip()))
                bad += 1
                break
        else:
            print("SELFTEST ok   %s %s crossover %s, both brackets as crband published" % (label, metric, m))
    print("SELFTEST %s" % ("FAILED" if bad else "PASSED"))
    return 1 if bad else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--selftest":
        sys.exit(selftest())
    if not args:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(args))
