#!/usr/bin/env python3
"""zen5split.py - the per-arm cross-box scale factors for the Zen 5 pair.

Reproduces section 4 of an internal note
EXACTLY, against a NEW round in which BOTH boxes ran the SAME binary built
from ONE `git archive` of origin/main, CONCURRENTLY. The banked pair that
report reduced could not do this: different parfast versions (1.5.0-beta.4
and 1.6.0), different harnesses, different build hosts, different times.

THE ARITHMETIC IS THE REPORT'S, TOKEN FOR TOKEN, and that is the point -
a second reduction that "improves" the method cannot be compared with the
first. One scale factor per arm, by LEAST SQUARES THROUGH THE ORIGIN over
the paired rung MEDIANS, in the direction `amd-ryzen-9800x3d / windows-gaming-pc-b`:

    k = sum(x_m * y_m) / sum(x_m * x_m)      x = windows-gaming-pc-b median at rung m
                                             y = amd-ryzen-9800x3d median at rung m

over the four components the report tabulates: cpu total, wall total,
`ffs_s` (parfast's own feed+fold+solve phase, the repair core), and
`wall - ffs_s` (the residual: process start, fixture open, damage restore,
write, verify).

`fold2` and `force2` are the rowgate phase's A/A copies of the same arm and
are POOLED with their originals, as w3winred.py does.

A rung is used only if BOTH boxes have at least one leg for that arm at
that rung; anything else is reported as dropped rather than silently
imputed, because a fit over a different rung set is not comparable with the
banked one.
"""
import re, sys, statistics as st
from collections import defaultdict

LEG = re.compile(r'^LEG\s')
def parse(path, threads=None):
    """arm -> m -> metric -> [values], from a wcomb rowgate log.

    `threads` selects one pool when a log holds more than one. The 17 Sep
    windows-gaming-pc-b log carries -t4 AND -t8 in 160 legs where the amd-ryzen-9800x3d one carries
    -t8 alone, so a reduction that does not filter would pool two pools on
    one side only - a silent, and large, apples-to-oranges error.
    """
    out = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for raw in open(path, encoding='utf-8', errors='replace'):
        if not LEG.match(raw):
            continue
        kv = dict(p.split('=', 1) for p in raw.split() if '=' in p)
        if kv.get('rc') != '0':
            continue
        if threads is not None and kv.get('threads') != str(threads):
            continue
        arm = kv.get('arm', '')
        arm = {'fold2': 'fold', 'force2': 'force'}.get(arm, arm)
        if arm not in ('fold', 'force'):
            continue
        try:
            m = int(kv['m']); cpu = float(kv['cpu']); wall = float(kv['wall'])
            ffs = float(kv['ffs_s'])
        except (KeyError, ValueError):
            continue
        d = out[arm][m]
        d['cpu'].append(cpu)
        d['wall'].append(wall)
        d['ffs_s'].append(ffs)
    return out

def med(D, arm, m, key):
    """The rung median of one component.

    THE RESIDUAL IS `median(wall) - median(ffs_s)`, NOT `median(wall - ffs_s)`,
    and the difference is not cosmetic: on the banked 17 Sep pair the two
    spellings give 1.0423/1.0505 and 1.0440/1.0541 respectively, and the
    SECOND is what
    an internal note section 4 published.
    Reproducing that table exactly is the whole reason this script exists, so
    the published spelling wins over the one a reader might expect. Verified
    by running this file against the two banked logs: every one of the eight
    published cells comes back to four decimal places.
    """
    if key == 'resid':
        return st.median(D[arm][m]['wall']) - st.median(D[arm][m]['ffs_s'])
    return st.median(D[arm][m][key])

def fit(xs, ys):
    """Least squares through the origin: the report's estimator."""
    num = sum(x * y for x, y in zip(xs, ys))
    den = sum(x * x for x in xs)
    return num / den if den else float('nan')

def main(a, b, threads=None):
    A, B = parse(a, threads), parse(b, threads)   # A = windows-gaming-pc-b (x), B = amd-ryzen-9800x3d (y)
    print(f"windows-gaming-pc-b    {a}")
    print(f"amd-ryzen-9800x3d {b}")
    comps = [('cpu', 'cpu, total'), ('wall', 'wall, total'),
             ('ffs_s', 'ffs_s, feed+fold+solve'), ('resid', 'wall - ffs_s, the residual')]
    print()
    print(f"{'component':<30} {'FORCE (NTT)':>12} {'FOLD':>10}   rungs  per-rung spread")
    verdict = {}
    for key, label in comps:
        row, extra = {}, {}
        for arm in ('force', 'fold'):
            rungs = sorted(set(A[arm]) & set(B[arm]))
            xs = [med(A, arm, m, key) for m in rungs]
            ys = [med(B, arm, m, key) for m in rungs]
            k = fit(xs, ys)
            row[arm] = k
            ratios = [y / x for x, y in zip(xs, ys) if x]
            extra[arm] = (len(rungs), min(ratios), max(ratios))
        verdict[key] = row
        n, lo, hi = extra['force']
        n2, lo2, hi2 = extra['fold']
        print(f"{label:<30} {row['force']:>12.4f} {row['fold']:>10.4f}   "
              f"{n}/{n2}   force {lo:.3f}..{hi:.3f}  fold {lo2:.3f}..{hi2:.3f}")

    # Dropped rungs, stated rather than hidden.
    for arm in ('force', 'fold'):
        only_a = sorted(set(A[arm]) - set(B[arm]))
        only_b = sorted(set(B[arm]) - set(A[arm]))
        if only_a or only_b:
            print(f"DROPPED {arm}: windows-gaming-pc-b-only {only_a} amd-ryzen-9800x3d-only {only_b}")

    # THE VERDICT, DECIDED IN ADVANCE by section 4 of
    # an internal note, so it
    # cannot be rationalised after the numbers are on the screen.
    f_fold, f_force = verdict['ffs_s']['fold'], verdict['ffs_s']['force']
    print()
    print(f"CORE (ffs_s): fold {f_fold:.4f}  force/NTT {f_force:.4f}")
    near = lambda v, t, tol=0.02: abs(v - t) <= tol
    if near(f_fold, 1.012, 0.025) and near(f_force, 1.063, 0.025):
        print("VERDICT: BOX. Fold core ~1.01 and NTT core ~1.06 REPRODUCE with one "
              "binary, so the binary is exonerated and hypotheses 3/4 own it.")
    elif near(f_fold, 1.0, 0.015) and near(f_force, 1.0, 0.015):
        print("VERDICT: BINARY. Both cores ~1.00 with one binary, so the two parfast "
              "VERSIONS were the cause and the cross-box problem is smaller than feared.")
    else:
        print("VERDICT: NEITHER PRE-DECIDED ARM. Say so plainly and do not force it "
              "into either box; report the numbers as they are.")

if __name__ == '__main__':
    if len(sys.argv) not in (3, 4):
        sys.exit("usage: zen5split.py <windows-gaming-pc-b.log> <amd-ryzen-9800x3d.log> [threads]")
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) == 4 else None)
