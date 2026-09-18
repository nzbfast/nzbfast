#!/usr/bin/env python3
"""memcross.py - the PAIRED reducer for memladder.py's fold/force crossover.

    memcross.py legs.jsonl [budget] [metric]      # metric: cpu (default) or wall

WHY PAIRED, and why this file exists rather than a median per arm. The
deliverable of a memladder round is a CROSSOVER RUNG - the m at which `force`
(the transform) overtakes `fold` - and at a crossover the two arms are equal by
construction, so the drift a shared box adds between two legs is not a rounding
digit, it is the answer. An UNPAIRED median of a noisy arm is exactly what
produced the wrong number on 17 Sep 2026: a +4.29% cpu delta for a change whose
whole cost is 770 rate-limited calls, with the SILENT control arm reading +4.15%
beside it (an internal note sections 6-8).

So the statistic here is the PER-REP DIFFERENCE. Within one rep, at one rung and
one budget, the arms run seconds apart on identical damage (memladder seeds
`damage_picks` at 1000+m, once per rung per rep, and every arm of that rep gets
the same picks), so box drift on any scale longer than a rep is differenced away.
Reported as the MEDIAN of those differences plus a SIGN TEST - the count of reps
whose difference has the winning sign, against an exact two-sided binomial. The
sign test is what a shared box's drift cannot fake: to move it, drift has to
change the ORDER of the two arms within a rep, in the same direction, in most
reps.

AND THE POSITION EFFECT IS MEASURABLE HERE, which is the point of rotating the
arm order rather than merely de-biasing it. With the order rotating one step a
rep, each arm lands in each position an equal number of times, so a TWO-WAY
decomposition - divide out the arm's own level, then the rep's - estimates what
running first, second or third is worth on this box. It must be two-way: under a
rotation arm and position are perfectly confounded INSIDE a rep, so a
deviation-from-the-rep-mean reads the dearest ARM as a position effect (it
reported +6 to +10% against an injected +3% on this file's own synthetic arm
before it was fixed, 17 Sep 2026). That number is what
prices a FIXED-ORDER round retrospectively: a fixed-order reading carries the
position-1-minus-position-2 effect as a systematic term, undifferenced and
invisible. A round that only rotated could report a corrected answer; a round
that rotates AND reports this can also say how wrong the old one was.

`ok` is gated: a leg that did not restore the pristine bytes is not a timing.
"""
import collections
import json
import math
import statistics
import sys


def sign_test(pos, n):
    """Exact two-sided binomial p for `pos` successes in `n` trials at p=0.5."""
    if not n:
        return 1.0
    k = min(pos, n - pos)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2.0 ** n
    return min(1.0, 2.0 * tail)


def main(path, budget=None, metric="cpu"):
    rows = [json.loads(line) for line in open(path)]
    bad = [r for r in rows if not r.get("ok")]
    rows = [r for r in rows if r.get("ok")]
    if budget:
        rows = [r for r in rows if str(r["budget"]) == str(budget)]
    if not rows:
        raise SystemExit("no ok legs in %s for budget=%s" % (path, budget))

    print("== %s  budget=%s  metric=%s  %d ok leg(s), %d refused"
          % (path, budget or "(all)", metric, len(rows), len(bad)))
    orders = {r.get("arm_order") for r in rows}
    print("   arm_order=%s" % ",".join(sorted(str(o) for o in orders)))
    l0 = [r["load_before"] for r in rows]
    l1 = [r["load_after"] for r in rows]
    print("   load_before min/median/max %.1f/%.1f/%.1f   load_after %.1f/%.1f/%.1f"
          % (min(l0), statistics.median(l0), max(l0), min(l1), statistics.median(l1), max(l1)))

    # -- the rotation, PROVED from the banked legs rather than from the source.
    cells = collections.Counter((r["arm"], r["arm_pos"]) for r in rows)
    counts = sorted(set(cells.values()))
    print("\n-- rotation, as banked --")
    arms = sorted({r["arm"] for r in rows})
    print("   %-6s %s" % ("arm", "  ".join("pos%d" % p for p in range(len(arms)))))
    for a in arms:
        print("   %-6s %s" % (a, "  ".join("%4d" % cells[(a, p)] for p in range(len(arms)))))
    print("   %s (counts %s)"
          % ("BALANCED: every arm in every position equally often" if len(counts) == 1
             else "NOT BALANCED - a position term survives in the arm means", counts))

    # -- the paired statistic, per rung.
    print("\n-- paired per-rep difference, fold minus force (positive = force is cheaper) --")
    print("   %6s %5s %10s %10s %9s %9s %8s  %s"
          % ("m", "reps", "fold med", "force med", "med diff", "med %", "sign", "p"))
    verdicts = {}
    for m in sorted({r["m"] for r in rows}):
        by = collections.defaultdict(dict)
        for r in rows:
            if r["m"] == m:
                by[r["rep"]][r["arm"]] = r[metric]
        diffs = [(v["fold"] - v["force"]) for v in by.values() if "fold" in v and "force" in v]
        folds = [v["fold"] for v in by.values() if "fold" in v]
        forces = [v["force"] for v in by.values() if "force" in v]
        if not diffs:
            continue
        med = statistics.median(diffs)
        pos = sum(d > 0 for d in diffs)
        p = sign_test(pos, len(diffs))
        pct = 100.0 * med / statistics.median(folds)
        verdicts[m] = (med, pos, len(diffs), p)
        print("   %6d %5d %10.2f %10.2f %+9.3f %+8.2f%% %4d/%-3d %7.4f%s"
              % (m, len(diffs), statistics.median(folds), statistics.median(forces),
                 med, pct, pos, len(diffs), p, "" if p < 0.05 else "   (not significant)"))

    # -- where the crossover falls, read off the signed verdicts.
    print("\n-- crossover --")
    rungs = sorted(verdicts)
    fold_wins = [m for m in rungs if verdicts[m][0] < 0 and verdicts[m][3] < 0.05]
    force_wins = [m for m in rungs if verdicts[m][0] > 0 and verdicts[m][3] < 0.05]
    ties = [m for m in rungs if verdicts[m][3] >= 0.05]
    print("   fold wins (significant):  %s" % (fold_wins or "none"))
    print("   ties (sign test n.s.):    %s" % (ties or "none"))
    print("   force wins (significant): %s" % (force_wins or "none"))
    if fold_wins and force_wins:
        print("   => crossover is between m=%d and m=%d" % (max(fold_wins), min(force_wins)))
    elif force_wins and not fold_wins:
        print("   => force already wins at the lowest rung measured (m=%d): crossover is BELOW the ladder"
              % min(rungs))

    # -- the position effect. TWO-WAY, and it has to be: under a rotation the
    # -- arm and the position are perfectly confounded WITHIN a rep, so
    # -- deviation-from-the-rep-mean does NOT cancel the arm - whichever arm is
    # -- dearest simply loads onto whichever position it happens to hold. So
    # -- divide out the ARM's own level first (each arm holds each position
    # -- equally often, which is what makes this legitimate), then divide out
    # -- each REP's level (every position appears in every rep, so drift
    # -- cancels), and only then read the position medians.
    print("\n-- position effect (arm level and rep level divided out; what running Nth is worth) --")
    print("   %6s %s" % ("m", "  ".join("%13s" % ("pos%d" % p) for p in range(len(arms)))))
    for m in sorted({r["m"] for r in rows}):
        legs = [r for r in rows if r["m"] == m]
        arm_lvl = {a: statistics.median([r[metric] for r in legs if r["arm"] == a]) for a in arms}
        ratio = {}
        for r in legs:
            ratio[(r["rep"], r["arm_pos"])] = r[metric] / arm_lvl[r["arm"]]
        reps = sorted({k[0] for k in ratio})
        dev = collections.defaultdict(list)
        for rep in reps:
            vals = {p: ratio[(rep, p)] for p in range(len(arms)) if (rep, p) in ratio}
            if len(vals) != len(arms):
                continue
            lvl = statistics.fmean(vals.values())
            for pos, v in vals.items():
                dev[pos].append(100.0 * (v - lvl) / lvl)
        meds = [statistics.median(dev[p]) for p in range(len(arms))]
        print("   %6d %s   pos0-pos1=%+.2f%%" % (m, "  ".join("%+12.2f%%" % v for v in meds), meds[0] - meds[1]))
    print("   The levels are centred, so the READABLE quantity is the GAP: pos0-pos1 is what")
    print("   the first slot cost the arm that held it, and is the term a fixed order banks.")
    print("   (a FIXED-order round carries pos0-minus-pos1 as a systematic term it cannot see:")
    print("    on this driver until 17 Sep 2026 that term sat entirely on `fold`, which ran first)")

    if bad:
        print("\n!! %d leg(s) did not gate and are excluded: %s"
              % (len(bad), ", ".join(sorted({"m%d-%s-r%d" % (r["m"], r["arm"], r["rep"]) for r in bad}))))


if __name__ == "__main__":
    main(*sys.argv[1:])
