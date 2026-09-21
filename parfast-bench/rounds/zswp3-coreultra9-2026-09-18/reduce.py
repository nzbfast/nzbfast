#!/usr/bin/env python3
"""Reduce a swpcore.ps1 create-sweep log (zswp2 / zswp3 family).

Per cell (size, redundancy): the three arms' walls, `parfast-mcap` against
`parfast` in percent, and every leg's `foreign_cpu`. Then the position term:
each leg's wall is expressed as a log-ratio to its own cell's mean over the
three arms, and those residuals are averaged BY POSITION - which is only
separable from the arm when the driver rotated (arm_pos banked on the CC
line, each arm in each position the same number of times). On a fixed-order
log (zswp2) position and arm are the same column, and the script says so.

Usage: reduce.py <log> [<published log to compare against>]
"""
import re, sys, math, statistics as st
from collections import defaultdict

def parse(path):
    rows = []
    for l in open(path, encoding='utf-8', errors='replace'):
        # harness-rig-gate: a reducer. It reads the CC lines of a banked round
        #   it is handed and banks no round log of its own.
        if not l.startswith('CC '):
            continue
        l = re.sub(r"argv='[^']*'", '', l)
        d = dict(re.findall(r'(\w+)=(\S+)', l))
        d['size'] = int(d['size']); d['red'] = int(d['red'])
        d['wall'] = float(d['wall']); d['cpu'] = float(d['cpu'])
        d['fcpu'] = float(d.get('foreign_cpu', 'nan'))
        d['rc'] = int(d.get('rc', '-1'))
        rows.append(d)
    return rows

def cells_of(rows):
    cells = defaultdict(dict)
    order = defaultdict(list)
    for d in rows:
        k = (d['size'], d['red'])
        cells[k][d['arm']] = d
        order[k].append(d['arm'])
    for k in cells:
        for i, arm in enumerate(order[k], 1):
            cells[k][arm].setdefault('arm_pos', str(i))
    return cells

def main():
    rows = parse(sys.argv[1])
    cells = cells_of(rows)
    pub = cells_of(parse(sys.argv[2])) if len(sys.argv) > 2 else None
    arms = ['parfast', 'parfast-mcap', 'turbo']
    rotated = all('arm_order' in d for d in rows) and any(d.get('arm_order') != 'fixed' for d in rows)

    # ARM-ORDER census: each arm at each position how many times
    cnt = defaultdict(int)
    for d in rows:
        cnt[(d['arm'], int(d['arm_pos']))] += 1
    print('ARM-ORDER  (arm, position) -> legs   [rotated=%s]' % rotated)
    for a in arms:
        print('  %-13s' % a, '  '.join('pos%d=%d' % (p, cnt[(a, p)]) for p in (1, 2, 3)))
    balanced = all(cnt[(a, p)] == cnt[(arms[0], 1)] for a in arms for p in (1, 2, 3))
    print('  balanced=%s' % balanced)
    bad = [d for d in rows if d['rc'] != 0]
    print('  legs=%d nonzero_rc=%d' % (len(rows), len(bad)))

    print()
    hdr = 'size red |  parfast    mcap   turbo | mcap/pf %% | pos p/m/t | fcpu p/m/t'
    if pub: hdr += ' | published mcap/pf %  delta pp'
    print(hdr)
    deltas = []; pubdeltas = []
    for k in sorted(cells):
        c = cells[k]
        if not all(a in c for a in arms):
            print('%3d %3d | INCOMPLETE %s' % (k[0], k[1], sorted(c)))
            continue
        p, m, t = (c[a]['wall'] for a in arms)
        pct = 100 * (m / p - 1); deltas.append(pct)
        line = '%3d %3d | %8.2f %7.2f %7.2f | %+8.1f | %s/%s/%s | %s/%s/%s' % (
            k[0], k[1], p, m, t, pct,
            c['parfast']['arm_pos'], c['parfast-mcap']['arm_pos'], c['turbo']['arm_pos'],
            c['parfast']['fcpu'], c['parfast-mcap']['fcpu'], c['turbo']['fcpu'])
        if pub and k in pub and all(a in pub[k] for a in arms):
            pp = 100 * (pub[k]['parfast-mcap']['wall'] / pub[k]['parfast']['wall'] - 1)
            pubdeltas.append(pp)
            line += ' | %+8.1f  %+7.1f' % (pp, pct - pp)
        print(line)

    if deltas:
        print()
        print('mcap/parfast %%: median %+.1f  mean %+.1f  n=%d' % (st.median(deltas), st.mean(deltas), len(deltas)))
        small = [(k, 100 * (cells[k]['parfast-mcap']['wall'] / cells[k]['parfast']['wall'] - 1))
                 for k in sorted(cells) if k[0] <= 20 and all(a in cells[k] for a in arms)]
        if small:
            print('  in-RAM cells (size <= 20 GiB, peak under the 31.4 GB box): median %+.1f  mean %+.1f  n=%d'
                  % (st.median([v for _, v in small]), st.mean([v for _, v in small]), len(small)))
    if pubdeltas:
        print('  published on the same cells: median %+.1f  mean %+.1f' % (st.median(pubdeltas), st.mean(pubdeltas)))

    # position term: cell-centred log-wall residual, by position and by arm
    print()
    bypos = defaultdict(list); byarm = defaultdict(list); byarmpos = defaultdict(list)
    for k, c in cells.items():
        if not all(a in c for a in arms):
            continue
        # centre on the two parfast arms only: turbo is 3-10x slower and would
        # swamp a cell mean; the pair is what the position term is asked for
        pair = [c['parfast'], c['parfast-mcap']]
        mu = st.mean(math.log(d['wall']) for d in pair)
        for d in pair:
            r = 100 * (math.log(d['wall']) - mu)
            bypos[int(d['arm_pos'])].append(r); byarm[d['arm']].append(r); byarmpos[(d['arm'], int(d['arm_pos']))].append(r)
    print('POSITION TERM over the parfast/parfast-mcap pair (cell-centred log-wall residual, in %)')
    if not rotated:
        print('  (fixed-order log: position and arm are the same column here, so this is NOT a position term)')
    for p in sorted(bypos):
        v = bypos[p]
        print('  pos%d: mean %+6.2f  median %+6.2f  n=%d' % (p, st.mean(v), st.median(v), len(v)))
    for a in ('parfast', 'parfast-mcap'):
        v = byarm[a]
        print('  %-13s mean %+6.2f  median %+6.2f  n=%d' % (a, st.mean(v), st.median(v), len(v)))
    print('  by (arm, pos):')
    for a in ('parfast', 'parfast-mcap'):
        print('   %-13s' % a, '  '.join('pos%d=%+6.2f(n=%d)' % (p, st.mean(byarmpos[(a, p)]), len(byarmpos[(a, p)]))
                                       for p in sorted({q for (_, q) in byarmpos}) if byarmpos.get((a, p))))
    # foreign_cpu by position
    fp = defaultdict(list)
    for d in rows:
        if not math.isnan(d['fcpu']): fp[int(d['arm_pos'])].append(d['fcpu'])
    print()
    print('foreign_cpu by position (percent of one core): ' + '  '.join(
        'pos%d median %.1f mean %.1f max %.1f' % (p, st.median(fp[p]), st.mean(fp[p]), max(fp[p])) for p in sorted(fp)))

if __name__ == '__main__':
    main()
