#!/usr/bin/env python3
"""cellcount.py - the census's own cell tally, DERIVED rather than asserted.

WHY THIS EXISTS. The first draft of the census section carried a headline of
"282 of 289", tallied by hand while the per-table counts were being collected.
It was WRONG, and wrong in the direction that flatters: the two largest
row-gate tables each carry a fold, a force and an F/T column for BOTH pools,
and the hand tally had counted one pool. The real figure is 332 of 339. A
census that miscounts its own population is the defect it exists to look for,
so the number now comes from a table somebody can check against the published
sections rather than from arithmetic done once in a transcript.

NO `--selftest` ARM, deliberately: this is a tally of a hand-read population,
so there is nothing here a machine can verify that reading the sections would
not verify better. It is a report, in the sense tools/layout-coverage.py's
header uses - run it, read it, check it against the notes.

Each row is (published table, cells re-derived, cells that did NOT reproduce).
A "cell" is one number a published table prints. The counts are per the
published tables in an internal note and
an internal note; the re-runs behind them are
banked in out/.
"""
import sys

ROWS = [
    # 8.17, the leaf-term round
    ("8.17.4 census, 64 KiB (9 rungs x fill-triple + additive)",     9 * 2,  0),
    ("8.17.5 three timing arms (2 slopes + 2 r2, x3)",               3 * 4,  0),
    ("8.17.5 per-window charge, 14,856..31,206",                        15,  0),
    ("8.17.5 the two secants quoted in prose",                           2,  0),
    # 8.18, the guest m ladder
    ("8.18.5 the ladder (14 rungs x 5 numeric) + 14 window splits", 14*5+14, 0),
    ("8.18.4 diagnostics (leaf spread, above-tile slope)",               2,  0),
    ("8.18.6 the joint fit + both controls",                            11,  0),
    ("8.18.6 steal ladder: legs kept and r2",                           10,  0),
    ("8.18.6 steal ladder: best K",                                      5,  3),
    ("8.18.7 A/A floor of the day",                                      6,  0),
    # 8.21, the fixed-width ladder
    ("8.21.4 charge + 3 fits + corrected knees + percentages",  17+9+2+2,    0),
    ("8.21.4 the uncorrected pair",                                      2,  1),
    # 8.16.5, the one re-implemented reduction
    ("8.16.5 wall / cpu / peak (7 rungs x 3)",                       7 * 3,  0),
    ("8.16.5 ntt syndromes (7 rungs)",                                   7,  3),
    # the row-gate note
    ("'CPU crossover at n = 16,384' (3 blocks x 2 pools)",               6,  0),
    ("the 1 MiB ladder in full (4 rungs x 6 columns)",               4 * 6,  0),
    ("256 KiB at n = 16,384 (2 crossovers, under its own filter)",       2,  0),
    ("'The 256 KiB figure did not hold' (6 F/T + 2 A/A + 2 x-over)",    10,  0),
    ("EPYC 64 KiB (10 rungs x 6) + 4 crossovers + k at 2 pools",   10*6+4+2, 0),
    ("EPYC 1 MiB (2 crossovers)",                                        2,  0),
    ("the 16 Sep nibble k cells (183 / 241 / 249 / 395)",                4,  0),
]

# Counted but NOT auditable from the banked legs, so held out of the tally
# rather than folded into either side of it. See the census section.
REFUSALS = [
    ("8.17.5 additive-leaves column - the per-leg .err sidecars carrying "
     "[ntt-fill] were never committed", 15),
]


def main():
    w = max(len(r[0]) for r in ROWS)
    print("%-*s %7s %7s" % (w, "published table", "cells", "bad"))
    print("-" * (w + 16))
    for name, cells, bad in ROWS:
        print("%-*s %7d %7d" % (w, name, cells, bad))
    tot = sum(c for _, c, _ in ROWS)
    bad = sum(b for _, _, b in ROWS)
    print("-" * (w + 16))
    print("%-*s %7d %7d" % (w, "TOTAL re-derived", tot, bad))
    print()
    print("%d of %d cells reproduce exactly; %d do not." % (tot - bad, tot, bad))
    print()
    print("HELD OUT of the tally - re-derivable from no banked input:")
    for name, cells in REFUSALS:
        print("  %d cells  %s" % (cells, name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
