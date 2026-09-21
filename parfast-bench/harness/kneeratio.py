#!/usr/bin/env python3
"""Fold/force parallelism ratio per rung, and the KNEE statistic over it.

    kneeratio.py [--threads N] [--metric-pair] <rowgate.log> [<rowgate.log> ...]
    kneeratio.py --selftest

WHY THIS EXISTS. Two rounds that reduce the same quantity differently stop
being comparable, which is the trap this campaign has been paying for, and the
knee question is now being asked on two parts at once: the AVX2 nibble i5
(`rounds/wask-t4-nibble-2026-09-17/`, where the knee was found) and
the GFNI-256 Core Ultra (`rounds/poolladder4m-2026-09-17/`, where the
decisive no-SMT cell is owed - see
an internal note item 5). This is the one
implementation of the arithmetic. It reuses `waskred.py`'s `legs()` / `cell()`
rather than re-parsing LEG lines.

THE QUANTITY. Per arm, per rung: effective parallelism is `cpu / wall`, the
fold cell medianed over the `fold`/`fold2` legs and the force cell over
`force`/`force2`, and the reported ratio is `eff_fold / eff_force`.
**The ratio is invariant to dividing by the thread count**, because the same
divisor sits on both sides, so a `-t4` ratio and a `-t8` ratio compare directly
even though the efficiencies themselves do not. CPU-seconds do not compare
across core-class masks on a hybrid part; this ratio does, because it is taken
WITHIN one arm.

THE KNEE STATISTIC is the largest single-interval step in that ratio divided by
the next largest, on the published reading: 19.8x at the i5's `-t12` (a knee),
1.6x at its `-t4` (smooth decay). It needs at least THREE rungs - one rung is a
level, two rungs are one step with no "next" - and on both published arms the
largest and next-largest steps are the m=128->192 and 192->256 intervals, so
`-Rungs 128,192,256` reproduces both figures.

ONE CORRECTION THIS SCRIPT CARRIES. Recomputed from the banked log, the `-t12`
statistic is **16.3x**, not the 19.8x in the write-up. Neither figure is wrong
about the finding and the difference is arithmetic: 19.8x was taken from the
ratios as PRINTED to three decimals, and differencing rounded values inflates a
small "next" step. Quote the unrounded figure from here; both readings are far
outside the `-t4` control's 1.7x either way.

Both metrics matter and wall decides where they disagree (memory topic
`nzbfast-wall-time-is-the-deciding-metric`). This reduces the efficiency ratio,
which is built from BOTH, so there is no metric switch: report it beside the
wall and CPU crossovers, never instead of them.
"""
import os, sys

# NO BYTECODE, and it is the published tree that makes this load-bearing.
# `waskred` lives INSIDE website/, so importing it writes
# `rounds/wask-nibble-2026-09-16/__pycache__/waskred.cpython-NNN.pyc` next
# to it - into the tree that ships to the site. tools/site-leak-scan.py
# then walks website/ and REFUSES, correctly: a .pyc is not UTF-8 and not a
# container it can take apart, and a gate that cannot look inside must not
# report clean. So this step reddened `tool-selftests` on main with a file
# CI had just created itself, on every push, and a local
# `tools/preflight.py` run left the same artifact in the worktree.
# Reproduced both halves 18 Sep 2026; claim red-tool-selftests-d5da7c6b.
#
# Fixed at the SITE rather than by teaching the scan to skip __pycache__:
# the .pyc has no business in a published tree in the first place, and an
# exemption would be a hole the next generated binary falls through.
# Set BEFORE the import - Python consults it at import time, so after is
# too late.
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'rounds', 'wask-nibble-2026-09-16'))
import waskred as W  # noqa: E402


def ladder(path, threads=None):
    """[(m, eff_fold, eff_force, ratio)] for one log, one pool, ascending m."""
    ls = W.legs(path, threads=threads)
    out = []
    for m in sorted({int(x['m']) for x in ls}):
        ef = W.cell(ls, m, ('fold', 'fold2'), 'cpu') / W.cell(ls, m, ('fold', 'fold2'), 'wall')
        er = W.cell(ls, m, ('force', 'force2'), 'cpu') / W.cell(ls, m, ('force', 'force2'), 'wall')
        out.append((m, ef, er, ef / er))
    return out


def knee(rows):
    """(largest_step, next_step, ratio_or_None) over consecutive ratio steps."""
    if len(rows) < 3:
        return None
    mags = sorted((abs(rows[i + 1][3] - rows[i][3]) for i in range(len(rows) - 1)),
                  reverse=True)
    return mags[0], mags[1], (mags[0] / mags[1] if mags[1] else None)


def report(path, threads=None):
    rows = ladder(path, threads)
    label = os.path.basename(path) + (f' t{threads}' if threads else '')
    print(f'--- {label}  rungs={[r[0] for r in rows]}')
    for m, ef, er, r in rows:
        print(f'  m={m:4d}  fold_eff={ef:6.3f}  force_eff={er:6.3f}  ratio={r:.4f}')
    k = knee(rows)
    if k is None:
        print('  KNEE: not computable - fewer than three rungs, so there is one '
              'step and no next largest to divide by. A knee is a STEP against '
              'its neighbours, not a level.')
        return
    big, nxt, ratio = k
    verdict = 'KNEE' if ratio and ratio >= 10 else ('smooth decay' if ratio and ratio <= 3 else 'ambiguous')
    print(f'  KNEE: largest step {big:.4f}, next {nxt:.4f}, '
          f'largest/next = {ratio:.1f}x -> {verdict}')


def selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    log = os.path.join(here, '..', 'rounds', 'wask-t4-nibble-2026-09-17',
                       'i5-nibble-1m-n8192-resident-t4t12.log')
    # The published efficiency table, i5 nibble, resident ladder.
    want = {
        (4, 128): (5.22, 4.83), (4, 512): (4.34, 4.57),
        (12, 128): (10.70, 10.26), (12, 512): (6.67, 10.23),
    }
    for thr in (4, 12):
        rows = {r[0]: r for r in ladder(log, threads=thr)}
        for (t, m), (wf, wr) in want.items():
            if t != thr:
                continue
            _, ef, er, _ = rows[m]
            assert abs(ef - wf) <= 0.02, f't{t} m={m} fold {ef} != {wf}'
            assert abs(er - wr) <= 0.05, f't{t} m={m} force {er} != {wr}'
    k4 = knee(ladder(log, threads=4))
    k12 = knee(ladder(log, threads=12))
    assert k4[2] <= 3, f'-t4 control should read as smooth decay, got {k4[2]:.1f}x'
    assert k12[2] >= 10, f'-t12 should read as a knee, got {k12[2]:.1f}x'
    print(f'selftest OK - reproduces the published efficiency table; '
          f'-t4 {k4[2]:.1f}x (smooth), -t12 {k12[2]:.1f}x (knee)')


def main():
    a = sys.argv[1:]
    if not a or a[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    if a[0] == '--selftest':
        selftest()
        return 0
    threads = None
    if a[0] == '--threads':
        threads = int(a[1])
        a = a[2:]
    if not a:
        sys.exit('no logs given')
    for p in a:
        report(p, threads)
    return 0


if __name__ == '__main__':
    sys.exit(main())
