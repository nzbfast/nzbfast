#!/usr/bin/env python3
"""Price the fold-against-transform TRADE at every rung of a wcomb ladder.

WHAT THIS IS FOR. the maintainer's wall-time rule (memory topic
`nzbfast-wall-time-is-the-deciding-metric`) says wall beats CPU whenever the two
disagree, "unless there's something excessive and it's an extremely unfair
trade, like, 10x the cpu for a little bit better wall". The band between a
ladder's CPU crossover and its WALL crossover is the only region where the two
metrics disagree, so it is the only region where that limit can bite. Inside it
the transform is cheaper in CPU while the fold is faster in wall: choosing by
wall means choosing the fold and paying CPU for it, and the limit asks how much
CPU for how much wall.

`rounds/crpool4m-2026-09-17/README.md` tabulated that trade by hand
under "The PROPORTIONALITY LIMIT". This is the same quantity, mechanised, with
one thing that hand table did not have.

THE THING IT ADDS, AND IT IS THE WHOLE POINT. `rowgate.py read` computes an A/A
floor on CPU ONLY. The hand table's "fold wall gain +1.2%" at m=416 was
therefore quoted with no idea whether 1.2% clears the wall noise of that rung -
and a trade RATIO is a quotient of two small numbers, so it blows up exactly
where its denominator is least trustworthy. This reducer computes an A/A floor
on WALL as well, from the same fold/fold2 and force/force2 pairs, and marks a
rung UNRESOLVED when EITHER side of the ratio is inside its own floor.

READ AN `unres` AS A REFUSAL, NOT AS A SMALL TRADE. It says the instrument
cannot price this rung at this resolution, which is a publishable answer and is
what the proportionality limit needs to know. Widening a tolerance to turn one
into a number is the same edit as deleting the check.

SIGN AND BAND MEMBERSHIP. Inside the band, CPU F/T > 1 (the fold is dearer in
CPU) and wall F/T < 1 (the fold is faster). Outside it both point the same way,
the two metrics agree, and there is no trade to price: those rungs print with
`side=agree` and no ratio, because a ratio of two same-signed differences is not
the quantity the limit is about.

USAGE  python3 band-trade.py <wcomb log> [<wcomb log> ...]
It groups exactly as rowgate.py read does - by (label, phase, threads) - so a
ladder that ran two thread counts (an INTERLEAVED ladder) prints one table per
pool, and two ladders sharing a label would merge. Give every ladder a distinct
-Label; that is the same rule wcomb.ps1's header states for masks.
"""
import re
import statistics as st
import sys


LEG = re.compile(r'^LEG ')


def parse(paths):
    """Parse wcomb LEG lines directly.

    NOT via rowgate.py: that module reads os.environ["BIN"] at import time and
    its `read` only PRINTS medians, and this reducer needs the individual legs
    to compute a WALL A/A floor, which is the one thing it exists to add.
    """
    rows = []
    for path in paths:
        for ln in open(path, errors='replace'):
            if not LEG.match(ln):
                continue
            kv = dict(m.groups() for m in re.finditer(r'(\w+)=([^\s]*)', ln))
            if kv.get('phase') != 'create' and kv.get('phase') not in ('ladder', 'rowgate'):
                continue
            if kv.get('arm') not in ('fold', 'fold2', 'force', 'force2'):
                continue
            rows.append(dict(label=kv.get('label', ''), phase=kv['phase'],
                             threads=int(kv['threads']), m=int(kv['m']),
                             rep=int(kv['rep']), arm=kv['arm'], path=kv.get('path', ''),
                             cpu=float(kv['cpu']), wall=float(kv['wall']),
                             rc=int(kv.get('rc', '0'))))
    if not rows:
        sys.exit("REFUSED: no fold/force LEG lines in %s - failing to find is failing" % (paths,))
    return rows


def aa_floor(cells, field, base):
    """Worst |X - X2| / min over the reps, for `field`, on arm pair base/base2.

    The same definition rowgate.py uses for CPU, applied to whichever field is
    asked for. It is a MAX over reps and so is blind to a perturbation that hit
    both copies of a rung - which is why a tight floor is agreement and not
    correctness, and why every ladder here is also screened for monotonicity.
    """
    worst = 0.0
    for rep in {r["rep"] for r in cells}:
        a = [r[field] for r in cells if r["arm"] == base and r["rep"] == rep]
        b = [r[field] for r in cells if r["arm"] == base + "2" and r["rep"] == rep]
        if a and b:
            worst = max(worst, abs(a[0] - b[0]) / min(a[0], b[0]))
    return worst


def main(paths):
    lad = parse(paths)
    keys = sorted({(r["label"], r["phase"], r["threads"]) for r in lad})
    for key in keys:
        group = [r for r in lad if (r["label"], r["phase"], r["threads"]) == key]
        cells = {}
        for r in group:
            cells.setdefault(r["m"], []).append(r)
        print("== %s %s threads=%d   the fold-against-transform TRADE per rung" % key)
        print("   cost = fold CPU over force CPU, minus 1.  gain = 1 minus fold wall over force wall.")
        print("   ratio = cost / gain, the quantity the proportionality limit is stated in.")
        print("   %5s | %7s %7s | %7s %7s | %8s %8s | %7s | %s"
              % ("m", "cpuF/T", "wallF/T", "cost%", "gain%", "aa_cpu%", "aa_wall%", "ratio", "verdict"))
        for m in sorted(cells):
            c = cells[m]
            fold = [r for r in c if r["arm"] in ("fold", "fold2")]
            force = [r for r in c if r["arm"] in ("force", "force2")]
            if not fold or not force:
                continue
            for r in force:
                if r["path"] != "ntt":
                    sys.exit("REFUSED: force leg took the fold at m=%d: %s" % (m, r))
            for r in fold:
                if r["path"] != "fold":
                    sys.exit("REFUSED: fold leg took the transform at m=%d: %s" % (m, r))
            cF = st.median(r["cpu"] for r in fold)
            cT = st.median(r["cpu"] for r in force)
            wF = st.median(r["wall"] for r in fold)
            wT = st.median(r["wall"] for r in force)
            cpu_ratio, wall_ratio = cF / cT, wF / wT
            cost = (cpu_ratio - 1.0) * 100.0      # what the fold costs in CPU
            gain = (1.0 - wall_ratio) * 100.0     # what the fold buys in wall
            aacpu = max(aa_floor(c, "cpu", "fold"), aa_floor(c, "cpu", "force")) * 100.0
            aawall = max(aa_floor(c, "wall", "fold"), aa_floor(c, "wall", "force")) * 100.0
            in_band = cost > 0 and gain > 0
            if not in_band:
                verdict, shown = "agree", "     -"
            elif abs(cost) < aacpu or abs(gain) < aawall:
                verdict, shown = "unres", "     -"
            else:
                verdict, shown = "priced", "%6.1fx" % (cost / gain)
            print("   %5d | %7.3f %7.3f | %+7.1f %+7.1f | %8.1f %8.1f | %7s | %s"
                  % (m, cpu_ratio, wall_ratio, cost, gain, aacpu, aawall, shown, verdict))
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
