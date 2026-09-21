#!/usr/bin/env python3
"""nrdx.py - the PAIRED reducer for a wcomb.ps1 validate round with four arms.

    nrdx.py VALIDATE.log [--driver DRIVER.log] [--metric cpu|wall] [--min]

Written 18 Sep 2026 for lane ntt-narrow-x86-rotated-remeasure-18sep (census
row R2 of an internal note). It reduces the
rotated 18 Sep rounds in this directory AND the fixed-order 15 Sep rounds in
rounds/ntt-narrow-2026-09-15/ through one code path, so the two can
be compared statistic for statistic:

  * the rep of a leg is N from the preceding ROUND header's `tag=<tag>-rN`
    when the tag carries one (the 18 Sep driver runs one wcomb invocation per
    rep with -Reps 1, so every leg's own `rep=` reads 1), else the LEG line's
    own `rep=` field (the 15 Sep rounds, one invocation, -Reps 2). A LEG
    line's `round=` is the CELL tag and never names the invocation;
  * arm_pos is the leg's ordinal within its (rep, m) group by timestamp -
    the harness both rounds ran (wcomb.ps1 f49c2437...) banks no position
    field, so the position is DERIVED and, when --driver names the 18 Sep
    driver log, CHECKED against that log's NARROW-REP `arms=` line per rep;
  * a leg with rc != 0 or restored != 16/16 is refused and named, never
    averaged.

What it prints, per rung (CPU-seconds by default, --metric wall for wall):
  1. the rotation as banked (arm x position counts) and BALANCED / NOT;
  2. the box state: foreign_cpu before and after every leg and the load
     percentage either side, min / median / max, plus per-leg worst offenders;
  3. each arm's DECISION per rep (path, W, windows) and whether it was the
     same in every rep;
  4. PAIRED fold minus force: median of the per-rep difference, percent of
     the fold median, sign count, exact two-sided binomial p, and the
     crossover bracket read off the significant signs (memcross.py's method).
     A sign test at n = 4 bottoms out at p = 0.125, so the write-up must
     read the paired median against the spread (min / max diff also printed);
  5. PAIRED autoalt minus auto, i.e. base minus change (positive = the
     change is cheaper), the narrowing rule's verdict per rung;
  6. auto over min(fold, force) OF THE SAME REP, the brief's acceptance
     ratio, as a median of per-rep ratios;
  7. the position effect, two-way (arm level then rep level divided out),
     as memcross.py does it, readable only when the rotation is balanced;
  8. with --min, the 15 Sep note's table: MINIMUM over reps per cell, so the
     old statistic can be quoted beside the new one on the same legs.
"""
import argparse
import collections
import math
import re
import statistics
import sys


def read_lines(path):
    b = open(path, "rb").read()
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        txt = b.decode("utf-16")
    else:
        txt = b.decode("utf-8", errors="replace")
    return [l.lstrip("﻿") for l in txt.splitlines()]


def parse_legs(path):
    legs, refused = [], []
    inv_rep = None   # the rep an 18 Sep invocation carries in its ROUND tag (<tag>-rN)
    for line in read_lines(path):
        if line.startswith("ROUND "):
            mt = re.search(r"\btag=(\S+)", line)
            mr = re.search(r"-r(\d+)$", mt.group(1)) if mt else None
            inv_rep = int(mr.group(1)) if mr else None
            continue
        # harness-rig-gate: a reducer over a banked round's LEG lines; its
        #   output is a table, not a round log, so there is nothing for a stamp
        #   to head.
        if not line.startswith("LEG "):
            continue
        kv = {}
        for tok in line.split():
            i = tok.find("=")
            if i > 0:
                kv[tok[:i]] = tok[i + 1:]
        # `round=` on a LEG line is the CELL tag (m<m>-<budget>-<arm>-t<t>-r<rep>),
        # not the invocation's -Tag, so the rep comes from the last ROUND header
        # when that header's tag carries -rN (one invocation per rep), else from
        # the leg's own rep= field (one invocation, -Reps N).
        rep = inv_rep if inv_rep is not None else int(kv["rep"])
        r = {
            "round": kv["round"], "rep": rep, "m": int(kv["m"]), "arm": kv["arm"],
            "budget": kv["budget"], "rc": int(kv["rc"]), "restored": kv["restored"],
            "cpu": float(kv["cpu"]), "wall": float(kv["wall"]), "peak_mb": float(kv["peak_mb"]),
            "path": kv["path"], "ntt_w": kv.get("ntt_w", ""), "windows": kv.get("windows", ""),
            "foreign_cpu": float(kv.get("foreign_cpu", "nan")), "foreign_after": float(kv.get("foreign_after", "nan")),
            "load_before": float(kv.get("load_before", "nan")), "load_after": float(kv.get("load_after", "nan")),
            "ts": kv["ts"],
        }
        n_tot = r["restored"].split("/")[1] if "/" in r["restored"] else "?"
        if r["rc"] != 0 or r["restored"] != "%s/%s" % (n_tot, n_tot):
            refused.append(r)
        else:
            legs.append(r)
    return legs, refused


def assign_pos(legs):
    by = collections.defaultdict(list)
    for r in legs:
        by[(r["rep"], r["m"])].append(r)
    for key, rows in by.items():
        rows.sort(key=lambda r: r["ts"])
        for i, r in enumerate(rows):
            r["arm_pos"] = i
    return by


def driver_orders(path):
    orders = {}
    for line in read_lines(path):
        if line.startswith("NARROW-REP "):
            kv = dict(t.split("=", 1) for t in line.split() if "=" in t)
            orders[int(kv["rep"])] = kv["arms"].split(",")
    return orders


def sign_test(pos, n):
    if not n:
        return 1.0
    k = min(pos, n - pos)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2.0 ** n
    return min(1.0, 2.0 * tail)


def decision(r):
    if r["path"] == "fold":
        return "fold"
    return "W %s, %s win" % (r["ntt_w"], r["windows"])


def stat3(xs):
    xs = [x for x in xs if not math.isnan(x)]
    if not xs:
        return "n/a"
    return "%.1f / %.1f / %.1f" % (min(xs), statistics.median(xs), max(xs))


def paired(by, m, a, b, metric):
    """Per-rep a - b at rung m. Returns (diffs, a_values, b_values)."""
    diffs, av, bv = [], [], []
    for (rep, mm), rows in sorted(by.items()):
        if mm != m:
            continue
        d = {r["arm"]: r for r in rows}
        if a in d and b in d:
            diffs.append(d[a][metric] - d[b][metric]); av.append(d[a][metric]); bv.append(d[b][metric])
    return diffs, av, bv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--driver")
    ap.add_argument("--metric", default="cpu", choices=("cpu", "wall"))
    ap.add_argument("--min", action="store_true", help="also print the 15 Sep MIN-over-reps table")
    a = ap.parse_args()
    metric = a.metric
    legs, refused = parse_legs(a.log)
    if not legs:
        sys.exit("no gated legs in %s" % a.log)
    by = assign_pos(legs)
    arms = sorted({r["arm"] for r in legs})
    rungs = sorted({r["m"] for r in legs})
    reps = sorted({r["rep"] for r in legs})
    print("== %s  metric=%s  %d gated leg(s), %d refused, reps=%s, rungs=%s"
          % (a.log, metric, len(legs), len(refused), reps, rungs))
    for r in refused:
        print("   REFUSED m=%d rep=%d arm=%s rc=%d restored=%s" % (r["m"], r["rep"], r["arm"], r["rc"], r["restored"]))

    # 1. rotation
    print("\n-- arm order, as banked (position derived from LEG timestamps within each rep and rung) --")
    if a.driver:
        orders = driver_orders(a.driver)
        mism = 0
        for (rep, m), rows in sorted(by.items()):
            got = [r["arm"] for r in rows]
            want = orders.get(rep)
            if want and got != want:
                mism += 1
                print("   MISMATCH rep=%d m=%d legs=%s driver=%s" % (rep, m, got, want))
        for rep in sorted(orders):
            print("   rep %d driver NARROW-REP arms=%s" % (rep, ",".join(orders[rep])))
        print("   %d (rep, rung) group(s) disagree with the driver's banked order" % mism)
    cells = collections.Counter((r["arm"], r["arm_pos"]) for r in legs)
    npos = max(r["arm_pos"] for r in legs) + 1
    print("   %-8s %s" % ("arm", "  ".join("pos%d" % p for p in range(npos))))
    for arm in arms:
        print("   %-8s %s" % (arm, "  ".join("%4d" % cells[(arm, p)] for p in range(npos))))
    counts = sorted(set(cells[(arm, p)] for arm in arms for p in range(npos)))
    balanced = len(counts) == 1
    print("   %s (counts %s)" % ("BALANCED: every arm in every position equally often" if balanced
                                 else "NOT BALANCED - a fixed or partly fixed order; the position term survives in the arm means", counts))

    # 2. box state
    print("\n-- box state, min / median / max over all gated legs --")
    print("   foreign_cpu before leg (%% of one core, other processes): %s" % stat3([r["foreign_cpu"] for r in legs]))
    print("   foreign_cpu after leg:                                    %s" % stat3([r["foreign_after"] for r in legs]))
    print("   load_before (Win32_Processor LoadPercentage, whole box):  %s" % stat3([r["load_before"] for r in legs]))
    print("   load_after:                                               %s" % stat3([r["load_after"] for r in legs]))
    worst = sorted(legs, key=lambda r: -max(r["foreign_cpu"], r["foreign_after"]))[:5]
    print("   five legs with the most foreign CPU either side: %s"
          % ", ".join("m%d-%s-r%d %.0f/%.0f" % (r["m"], r["arm"], r["rep"], r["foreign_cpu"], r["foreign_after"]) for r in worst))
    print("   first leg ts=%s  last leg ts=%s" % (min(r["ts"] for r in legs), max(r["ts"] for r in legs)))

    # 3. decisions
    print("\n-- decisions per arm (path / stripe width W / window count), and whether every rep agreed --")
    for m in rungs:
        parts = []
        for arm in arms:
            ds = [decision(r) for r in legs if r["m"] == m and r["arm"] == arm]
            u = sorted(set(ds))
            parts.append("%s=%s%s" % (arm, u[0] if len(u) == 1 else "|".join(u), "" if len(u) == 1 else " DISAGREE"))
        print("   m=%-5d %s" % (m, "  ".join(parts)))

    # 4. paired fold - force
    def paired_table(title, a1, a2, note):
        print("\n-- %s --" % title)
        print("   %6s %4s %10s %10s %9s %8s %9s %9s %6s %7s" % ("m", "n", a1 + " med", a2 + " med", "med diff", "med %", "min diff", "max diff", "sign", "p"))
        verdicts = {}
        for m in rungs:
            diffs, av, bv = paired(by, m, a1, a2, metric)
            if not diffs:
                continue
            med = statistics.median(diffs)
            pos = sum(d > 0 for d in diffs)
            p = sign_test(pos, len(diffs))
            pct = 100.0 * med / statistics.median(av)
            verdicts[m] = (med, pos, len(diffs), p)
            print("   %6d %4d %10.2f %10.2f %+9.3f %+7.2f%% %+9.3f %+9.3f %3d/%-2d %7.4f%s"
                  % (m, len(diffs), statistics.median(av), statistics.median(bv), med, pct, min(diffs), max(diffs),
                     pos, len(diffs), p, "" if p < 0.05 else "  n.s."))
        print("   %s" % note)
        return verdicts

    v = paired_table("PAIRED fold minus force per rep (positive = force is cheaper)", "fold", "force",
                     "sign = reps where force was cheaper; p = exact two-sided binomial. At n=4 the floor is p=0.125.")
    fold_wins = [m for m in rungs if m in v and v[m][0] < 0 and v[m][1] == 0]
    force_wins = [m for m in rungs if m in v and v[m][0] > 0 and v[m][1] == v[m][2]]
    mixed = [m for m in rungs if m in v and m not in fold_wins and m not in force_wins]
    print("   unanimous fold:  %s" % (fold_wins or "none"))
    print("   mixed signs:     %s" % (mixed or "none"))
    print("   unanimous force: %s" % (force_wins or "none"))
    if fold_wins and force_wins:
        print("   => crossover (unanimous signs) is between m=%d and m=%d" % (max(fold_wins), min(force_wins)))
    elif force_wins and not fold_wins:
        print("   => force wins unanimously at the lowest rung measured (m=%d): the crossover is BELOW the ladder" % min(rungs))

    # 5. paired base - change
    if "auto" in arms and "autoalt" in arms:
        paired_table("PAIRED autoalt (base) minus auto (change) per rep (positive = the change is cheaper)", "autoalt", "auto",
                     "the narrowing rule's verdict: read only where the two arms DECIDED differently (section 3).")

    # 6. auto over best of fold/force of the same rep
    if "auto" in arms:
        print("\n-- auto over min(fold, force) OF THE SAME REP (the brief's acceptance ratio), median and range of per-rep ratios --")
        for m in rungs:
            ratios = []
            for (rep, mm), rows in sorted(by.items()):
                if mm != m:
                    continue
                d = {r["arm"]: r[metric] for r in rows}
                if "auto" in d and "fold" in d and "force" in d:
                    ratios.append(d["auto"] / min(d["fold"], d["force"]))
            if ratios:
                print("   m=%-5d n=%d median %.3f  range %.3f-%.3f" % (m, len(ratios), statistics.median(ratios), min(ratios), max(ratios)))

    # 7. position effect (two-way)
    print("\n-- position effect, two-way (arm level then rep level divided out): what running Nth is worth, per rung --")
    if not balanced:
        print("   NOT BALANCED: the arm-level division is not legitimate here; the table is printed for the record and must not be quoted as a position term.")
    print("   %6s %s   pos0-pos%d" % ("m", "  ".join("%9s" % ("pos%d" % p) for p in range(npos)), npos - 1))
    allmeds = []
    for m in rungs:
        rows = [r for r in legs if r["m"] == m]
        arm_lvl = {arm: statistics.median([r[metric] for r in rows if r["arm"] == arm]) for arm in arms}
        ratio = {(r["rep"], r["arm_pos"]): r[metric] / arm_lvl[r["arm"]] for r in rows}
        dev = collections.defaultdict(list)
        for rep in reps:
            vals = {p: ratio[(rep, p)] for p in range(npos) if (rep, p) in ratio}
            if len(vals) != npos:
                continue
            lvl = statistics.fmean(vals.values())
            for p, val in vals.items():
                dev[p].append(100.0 * (val - lvl) / lvl)
        if all(dev[p] for p in range(npos)):
            meds = [statistics.median(dev[p]) for p in range(npos)]
            allmeds.append(meds)
            print("   %6d %s   %+.2f%%" % (m, "  ".join("%+8.2f%%" % x for x in meds), meds[0] - meds[-1]))
    if allmeds:
        print("   across rungs, median by position: %s" % "  ".join("%+.2f%%" % statistics.median([mm[p] for mm in allmeds]) for p in range(npos)))
    print("   read the GAP between positions, not the levels (they are centred). A FIXED order banks pos0 minus the")
    print("   position each arm always held as a systematic term it cannot see.")

    # 8. MIN table
    if a.min:
        print("\n-- MINIMUM over reps per cell (the 15 Sep note's statistic), %s --" % metric)
        hdr = ["m"] + arms + ["auto/min(fold,force)", "autoalt/auto"]
        print("   " + " | ".join(hdr))
        for m in rungs:
            mins = {}
            for arm in arms:
                xs = [r[metric] for r in legs if r["m"] == m and r["arm"] == arm]
                if xs:
                    mins[arm] = min(xs)
            row = ["%d" % m] + ["%.2f" % mins.get(arm, float("nan")) for arm in arms]
            if "auto" in mins and "fold" in mins and "force" in mins:
                row.append("%.2f" % (mins["auto"] / min(mins["fold"], mins["force"])))
            else:
                row.append("")
            row.append("%.2f" % (mins["autoalt"] / mins["auto"]) if "auto" in mins and "autoalt" in mins else "")
            print("   " + " | ".join(row))


if __name__ == "__main__":
    main()
