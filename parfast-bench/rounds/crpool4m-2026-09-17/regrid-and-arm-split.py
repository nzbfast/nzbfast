#!/usr/bin/env python3
"""Why does the unpinned -t16 create crossover read 365 in one sitting and 387 in the next?

Written 18 Sep 2026 for lane `parfast-create-pool-ladder-4mib-17sep`, to attack a
discrepancy that lane's own round record stated and could not explain: its
unpinned `4mc-t16` arm read **387** CPU / 411 wall where `crg4-2026-09-16`'s
`-t16` read **365** / 393 - a 22-row swing on the SAME configuration, binary and
fixture shape, and LARGER than the entire 16-row gap the round was chartered to
investigate. The README named three candidates: a different rung grid (the
crossover is log-interpolated), a solo ladder against crg4's
two-pools-interleaved-in-one, and a different fixture instance.

NO BOX TIME. Both logs are banked; this only re-reduces them.

WHAT IT DOES. Two passes, in this order, because the first is a prerequisite for
trusting the second:

  1. RE-GRID. `rowgate.py read` log-interpolates the crossover over whatever
     rungs are present, so two ladders on different rung sets are not
     automatically comparable. crg4 ran 320..544 and this round ran 288..512.
     Both are filtered to the COMMON grid (320,352,384,416,448,480,512) and
     re-reduced. If the crossover moves, the grid was the story.
  2. ARM SPLIT. On that common grid, compare the fold arm and the force arm
     SEPARATELY, per rung, between the two sittings. A crossover is where
     fold/force = 1, so it only moves if the two arms move by DIFFERENT amounts.
     Symmetric noise cancels in the ratio and cannot produce a 22-row swing.

WHAT IT FOUND (18 Sep 2026):

  * THE RUNG GRID IS REFUTED, flatly. Every reading is identical on the common
    grid as on its own: crg4 -t16 stays 365/393, crg4 -t4 stays 381/422, this
    round's 4mc-t16 stays 387/411. Dropping rung 544 and rung 288 changes
    nothing. So the discrepancy is NOT a reduction artefact, which makes it
    more concerning rather than less.
  * THE TWO ARMS DID NOT MOVE TOGETHER. Between the sittings the FOLD arm is
    5.8% cheaper in CPU (6.1% in wall) and the FORCE arm only 3.0% (2.6%).
    That ~3 percentage-point differential is the whole crossover shift: the
    fold got relatively cheaper, so more rows are needed before the transform
    wins, and the crossing moves up.
  * THE DIVERGENCE IS LARGEST AT THE LOW RUNGS and shrinks as m rises (at
    m=320 fold -12.6% / force -9.9%; by m=480 fold -0.0% / force -0.3%). Those
    low crg4 rungs are also its noisiest - foreign CPU 22% at m=320 and 47% at
    m=352, against this round's 8% median.

WHAT IT DOES NOT SETTLE. It does not say WHY the fold moved more than the force.
Both candidates that survive pass 1 - interleaved-vs-solo and a different
fixture instance - remain live, and a third is now visible: crg4's sitting was
simply noisier (foreign CPU median 12% against 8%) and the noise did not hit the
two arms equally. Separating those needs a box.

WHY IT MATTERS BEYOND ONE NUMBER. The repair lane replicated its PINNED arms
across two independent sittings and got e4 344->349, e8 378->377, t16 398->401 -
within 5 rows. The UNPINNED create arm moved 22. So pinning buys reproducibility
as well as removing the placement confound, and that is an argument for pinning
that does not depend on the confound argument at all.

RUN:  python3 rounds/crpool4m-2026-09-17/regrid-and-arm-split.py
"""
import re, subprocess, sys, tempfile, pathlib

CRG  = 'rounds/crg4-2026-09-16/coreultra9-gfni256-create-4m-n4096-t4-t16-ladder.log'
MINE = 'rounds/crpool4m-2026-09-17/logs/crt16.log'
COMMON = {320, 352, 384, 416, 448, 480, 512}

ROW = re.compile(r'^\s*(\d+) \|\s*([\d.]+)\s+([\d.]+)\s+([\d.]+) \|'
                 r'\s*[\d.]+%\s+[\d.]+%\s+([\d.]+)% \| \S+\s+\|\s*([\d.]+)\s+([\d.]+)')


def filt(src, dst, keep, threads=None):
    """Keep only LEG lines at these rungs (and thread count); pass everything else."""
    out = []
    for ln in open(src, errors='replace'):
        # harness-rig-gate: a report script. It splits a banked round's LEG
        #   lines by arm and writes a table; it banks no round log of its own.
        if ln.startswith('LEG '):
            m = re.search(r' m=(\d+) ', ln)
            t = re.search(r' threads=(\d+) ', ln)
            if not m:
                continue
            if int(m.group(1)) not in keep:
                continue
            if threads is not None and int(t.group(1)) != threads:
                continue
        out.append(ln)
    pathlib.Path(dst).write_text(''.join(out))


def reduce(p):
    return subprocess.run(['python3', 'harness/rowgate.py', 'read', str(p)],
                          capture_output=True, text=True).stdout


def crossover(p):
    for ln in reduce(p).splitlines():
        g = re.search(r'CPU m ~ (\S+)\s+wall m ~ (\S+)', ln)
        if g:
            return g.group(1), g.group(2)
    return '?', '?'


def table(p):
    return {int(m.group(1)): dict(fc=float(m.group(2)), tc=float(m.group(3)),
                                  fw=float(m.group(6)), tw=float(m.group(7)))
            for m in map(ROW.match, reduce(p).splitlines()) if m}


def main():
    d = pathlib.Path(tempfile.mkdtemp(prefix='regrid-'))
    full_crg, full_mine = {320,352,384,416,448,480,512,544}, {288,320,352,384,416,448,480,512}

    print("== PASS 1: is the RUNG GRID the story? ==")
    print(f"   common grid: {sorted(COMMON)}\n")
    print(f"   {'ladder':<22}{'own grid':>16}{'common grid':>16}")
    print('   ' + '-' * 54)
    for name, src, thr, own in [('crg4 -t16', CRG, 16, full_crg),
                                ('crg4 -t4', CRG, 4, full_crg),
                                ('crpool 4mc-t16', MINE, None, full_mine)]:
        filt(src, d / 'own.log', own, thr)
        filt(src, d / 'com.log', COMMON, thr)
        a, b = crossover(d / 'own.log'), crossover(d / 'com.log')
        print(f"   {name:<22}{a[0] + '/' + a[1]:>16}{b[0] + '/' + b[1]:>16}")
    print("\n   -> identical in every case: THE GRID IS REFUTED.\n")

    filt(CRG, d / 'a.log', COMMON, 16)
    filt(MINE, d / 'b.log', COMMON, None)
    a, b = table(d / 'a.log'), table(d / 'b.log')

    for metric, kf, kt in (('CPU', 'fc', 'tc'), ('WALL', 'fw', 'tw')):
        print(f"== PASS 2 ({metric}): which ARM moved between the sittings? ==")
        print(f"   {'m':>5} | {'fold crg4':>10}{'fold mine':>10}{'d%':>8} |"
              f" {'force crg4':>11}{'force mine':>11}{'d%':>8}")
        print('   ' + '-' * 69)
        df, dt = [], []
        for m in sorted(set(a) & set(b)):
            x, y = a[m], b[m]
            f = (y[kf] / x[kf] - 1) * 100
            t = (y[kt] / x[kt] - 1) * 100
            df.append(f); dt.append(t)
            print(f"   {m:>5} | {x[kf]:>10.2f}{y[kf]:>10.2f}{f:>+7.1f}% |"
                  f" {x[kt]:>11.2f}{y[kt]:>11.2f}{t:>+7.1f}%")
        print('   ' + '-' * 69)
        mf, mt = sum(df) / len(df), sum(dt) / len(dt)
        print(f"   {'mean':>5} | {'':>20}{mf:>+7.1f}% | {'':>22}{mt:>+7.1f}%")
        print(f"   -> the arms moved by DIFFERENT amounts ({mf - mt:+.1f} pp), "
              f"which is what moves a ratio.\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
