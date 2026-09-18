#!/usr/bin/env python3
"""cstripesum.py - reduce a cstripe-i5.ps1 round to the table it decides on.

    harness/cstripesum.py [--ref <arm>] research/<round>/legs-*.jsonl

One row per cell and arm: the median of the reps, the min-max range beside it,
and the delta each pinned width shows against the cell's reference arm (w1024
by default, the shipped create default at 1 MiB and up on the x86 nibble arms).

THE RANGES ARE PRINTED BECAUSE THE MEDIANS ALONE DECIDE NOTHING.  This family's
own rule, from the repair round this one follows (NTT-X86-TRANSFORM-CPU-1MIB-
2026-09-15): a difference is worth acting on when the two arms' min-max ranges
are DISJOINT and the move is larger than the A/A floor the auto arm measures.
`sep` says which of the two it is - `disjoint` when every leg of one arm beats
every leg of the other, `overlap` when it does not.

The A/A floor is real here and not a formality: `auto` pins nothing, so ON THE
x86 NIBBLE ARMS at 1 MiB and up it runs the same W 1,024 the `w1024` arm pins,
and the gap between those two arms is the round's own noise on that cell.

BUT WHICH PAIR IS THE FLOOR IS A FACT ABOUT THE BOX, NOT ABOUT THIS SCRIPT, AND
READING IT WRONG REPORTS THE EFFECT AS THE NOISE. `auto` is a floor against
whichever arm pins the width that box would have chosen anyway. On a GFNI or an
aarch64 arm `default_stripe_words` returns 512 at every block size, so `auto`
runs W 512 there and the floor is auto-against-w512, while `w1024` is a FORCED
arm the binary would never pick - which is exactly what a round measuring the
additive leaf's width preference off the nibble arms wants it to be. Pass
`--ref w512` on such a round to get the floor, and read the default `--ref
w1024` run for the effect. Running only the default there leaves the `auto` row
looking like a floor when it is a real A/B, and the two readings differ by the
whole size of the effect.

LEAF FILL TRAVELS WITH EVERY ROW, AND SO DOES THE KERNEL SPLIT.  A width result
at fill 80 and one at fill 256 are answers to different questions - the second
is over the additive leaf and the first is not - so a reader must never see the
number without it.

AND THE KERNEL BELOW THE GATE IS NOT THE SAME ON EVERY ARM, WHICH IS WHY THE
ROW PRINTS d/p/a AND NOT JUST THE FILL.  Below the additive gate the x86 nibble
and NEON arms run the PAIRED leaf, but the whole GFNI family runs the DENSE one:
conjugate::enabled() defers to gf16::PreparedSources::enabled(), which requires
both !gfni256_available() and !avx512_gfni_available(), so a GFNI-256 or an
AVX-512 GFNI part has no paired leaf to reach. Two boxes compared below the gate
are therefore NOT running the same kernel, however equal their fills. Read the
d/p/a counts on the row, never the fill alone, and never carry another box's
kernel attribution across.
"""
import json
import statistics
import sys
from collections import OrderedDict


def load(paths):
    legs = []
    for p in paths:
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    legs.append(json.loads(line))
    return legs


def med(xs):
    return statistics.median(xs)


def main(argv):
    args = argv[1:]
    ref_arm = None
    if args and args[0] == "--ref":
        if len(args) < 3:
            print(__doc__)
            return 2
        ref_arm, args = args[1], args[2:]
    if not args:
        print(__doc__)
        return 2
    legs = load(args)
    if not legs:
        print("no legs")
        return 1
    cells = OrderedDict()
    for leg in legs:
        cells.setdefault(leg["label"], OrderedDict()).setdefault(leg["arm"], []).append(leg)
    rc = 0
    for label, arms in cells.items():
        any_leg = next(iter(next(iter(arms.values()))))
        fill = "leaves %s fill %s/%s/%s kernels d%s p%s a%s" % (
            any_leg.get("fill_leaves"), any_leg.get("fill_min"), any_leg.get("fill_median"),
            any_leg.get("fill_max"), any_leg.get("leaf_dense"), any_leg.get("leaf_paired"),
            any_leg.get("leaf_additive"))
        print("\n== %s  block=%s slices=%s rows=%s route=%s corpus=%s  %s" % (
            label, any_leg["block"], any_leg["slices"], any_leg["rows"],
            any_leg["route"], any_leg.get("corpus"), fill))
        # Every leg in a cell must agree on the fill and the route, or the
        # cell is two shapes wearing one label.
        for arm, ls in arms.items():
            for leg in ls:
                if (leg.get("fill_max"), leg["route"]) != (any_leg.get("fill_max"), any_leg["route"]):
                    print("  MIXED-CELL %s r%s: fill/route differs from the cell's first leg" % (arm, leg["rep"]))
                    rc = 1
        # A named --ref that a cell does not carry is an ERROR, not a silent
        # fallback: the whole point of naming it is that the wrong reference
        # reports the effect as the noise, so a typo must not read as a result.
        if ref_arm is not None:
            if ref_arm not in arms:
                print("  REF-MISSING %s: cell has arms %s" % (ref_arm, ", ".join(arms)))
                rc = 1
                continue
            ref = ref_arm
        else:
            ref = "w1024" if "w1024" in arms else next(iter(arms))
        refwall = med([l["wall"] for l in arms[ref]])
        refcpu = med([l["cpu"] for l in arms[ref]])
        print("  %-8s %3s %9s %-17s %9s %-17s %8s %8s %s" % (
            "arm", "n", "wall_med", "wall_range", "cpu_med", "cpu_range", "d_wall", "d_cpu", "sep"))
        for arm, ls in arms.items():
            walls = sorted(l["wall"] for l in ls)
            cpus = sorted(l["cpu"] for l in ls)
            if arm == ref:
                dw = dc = sep = "-"
            else:
                dw = "%+.1f%%" % ((med(walls) - refwall) * 100.0 / refwall)
                dc = "%+.1f%%" % ((med(cpus) - refcpu) * 100.0 / refcpu)
                rw = sorted(l["wall"] for l in arms[ref])
                rcp = sorted(l["cpu"] for l in arms[ref])
                wsep = walls[-1] < rw[0] or rw[-1] < walls[0]
                csep = cpus[-1] < rcp[0] or rcp[-1] < cpus[0]
                sep = ("wall+cpu" if wsep and csep else
                       "wall" if wsep else "cpu" if csep else "overlap")
            print("  %-8s %3d %9.2f %-17s %9.2f %-17s %8s %8s %s" % (
                arm, len(ls), med(walls), "%.2f-%.2f" % (walls[0], walls[-1]),
                med(cpus), "%.1f-%.1f" % (cpus[0], cpus[-1]), dw, dc, sep))
        ntts = {a: med([l["ntt_s"] for l in ls]) for a, ls in arms.items()}
        print("  transform median s: " + ", ".join("%s %.2f" % (a, v) for a, v in ntts.items()))
        peaks = {a: med([l["peak_mb"] for l in ls]) for a, ls in arms.items()}
        print("  peak working set MB: " + ", ".join("%s %.0f" % (a, v) for a, v in peaks.items()))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
