#!/usr/bin/env python3
"""foldpar.py - reduce wcomb.ps1 `-Phase measure` LEG lines to the FOLD's
effective parallelism, which is what lane fold-parallelism-knee-18sep is about
and which no existing reducer prints.

    foldpar.py LOG [LOG...]              the per-cell table plus the verdict block
    foldpar.py --csv LOG [LOG...]        the same cells as csv, for pasting

WHY THIS IS NOT wcombsum.py. That reducer answers "what are the constants" -
c_f, c_l, c_w and k - by FITTING A SLOPE in m across rungs. This one answers
"does the pool pay", which is a per-cell ratio and not a fit, so it has no rung
set, no free parameter and nothing to state beside it. The two are complements:
a c_f that rises with the pool and an efficiency that falls with the pool are
the same fact seen from two ends, and this file is the end the chip asked about.

THE QUANTITY. For one leg,

    P    = cpu / wall            effective parallelism, threads' worth of work
                                 actually overlapped
    eff  = P / threads           the fraction of the pool that paid

`cpu` is whole-process CPU (user + kernel) off the process handle and `wall` is
the leg's own stopwatch, both already on the LEG line, so this is arithmetic on
banked fields and adds no instrument.

MINIMUM OVER REPS, BY WALL. Every cell is the rep with the SMALLEST wall, which
is wcombsum.py's convention and for its reason: a rep perturbed by something
foreign is slower, never faster, so the minimum is the best estimate of the
quiet cost. The spread across reps is printed beside it, because a cell whose
reps disagree by more than the effect being read is not a reading.

WHAT THE VERDICT BLOCK COMPARES, AND WHY IT IS THE FOLD/FORCE RATIO. On a
HYBRID part an unpinned pool ladder confounds pool size with core class: at
-t12 on a 4P+8E+4LP-E box, twelve threads are not twelve of anything. The
fold-vs-force ratio WITHIN one cell cancels that to first order, because both
arms run at the same rung, in the same sitting, under the same placement - so
whatever mix an unpinned -t12 lands on, both arms land on it. That is the
instrument the i5's own control used to refute a bandwidth threshold
(the -t12 FORCE arm held 8.89 at a LARGER footprint than the collapsing fold
cell), and it transfers to a hybrid part unchanged. A PINNED, single-class
ladder needs no such cancellation and its raw `eff` column is readable directly.

REFUSALS, NOT REPAIRS. A leg with rc != 0, or whose SHA gate did not restore
every member, is dropped and counted rather than reduced - a damaged leg's wall
is not a measurement of anything. A log with no LEG lines REFUSES (exit 2)
instead of printing an empty table, because an empty table reads like a result.
That is the same rule harness/rowgate.py applies to a UTF-16 log.

CPU-SECONDS DO NOT COMPARE ACROSS AFFINITY MASKS. `affinity` is carried into
the group key and printed on every row for exactly that reason. Two masks are
two tables that happen to be in one file; never read a raw `cpu` across them.
"""
import re
import sys
from collections import defaultdict

FIELD = re.compile(r'(\w+)=([^\s]*)')


def parse(path):
    """Return (legs, refused, reasons). A LEG line is a flat key=value bag."""
    legs, refused, reasons = [], 0, defaultdict(int)
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            # harness-rig-gate: a reducer. It folds the LEG lines of a banked
            #   round it is handed and writes no round log, so it has nothing
            #   to stamp.
            if not line.startswith('LEG '):
                continue
            d = dict(FIELD.findall(line))
            if d.get('rc') != '0':
                refused += 1
                reasons['rc=' + str(d.get('rc'))] += 1
                continue
            restored = d.get('restored', '')
            if '/' in restored:
                good, want = restored.split('/', 1)
                if good != want:
                    refused += 1
                    reasons['restored=' + restored] += 1
                    continue
            try:
                d['_wall'] = float(d['wall'])
                d['_cpu'] = float(d['cpu'])
                d['_m'] = int(d['m'])
                d['_threads'] = int(d['threads'])
            except (KeyError, ValueError):
                refused += 1
                reasons['unparsable'] += 1
                continue
            if d['_wall'] <= 0:
                refused += 1
                reasons['wall<=0'] += 1
                continue
            legs.append(d)
    return legs, refused, reasons


def cells(legs):
    """Group to one cell per (label, affinity, threads, arm, budget, m)."""
    by = defaultdict(list)
    for d in legs:
        key = (d.get('label', ''), d.get('affinity', '') or 'unpinned',
               d['_threads'], d.get('arm', ''), d.get('budget', ''), d['_m'])
        by[key].append(d)
    out = {}
    for key, group in by.items():
        best = min(group, key=lambda d: d['_wall'])
        walls = [d['_wall'] for d in group]
        spread = (max(walls) - min(walls)) / min(walls) * 100.0 if len(walls) > 1 else 0.0
        out[key] = {
            'wall': best['_wall'],
            'cpu': best['_cpu'],
            'P': best['_cpu'] / best['_wall'],
            'eff': best['_cpu'] / best['_wall'] / best['_threads'],
            'peak_mb': float(best.get('peak_mb', 'nan') or 'nan'),
            'reps': len(group),
            'spread_pct': spread,
            'foreign': best.get('foreign_cpu', ''),
        }
    return out


def main(argv):
    as_csv = '--csv' in argv
    paths = [a for a in argv if not a.startswith('--')]
    if not paths:
        print(__doc__.strip().splitlines()[1], file=sys.stderr)
        print('usage: foldpar.py [--csv] LOG [LOG...]', file=sys.stderr)
        return 2

    legs, refused, reasons = [], 0, defaultdict(int)
    for p in paths:
        l, r, rs = parse(p)
        legs += l
        refused += r
        for k, v in rs.items():
            reasons[k] += v
    if not legs:
        print('REFUSING: no usable LEG line in %s. An empty table reads like a '
              'result, so this refuses instead of printing one.' % ', '.join(paths),
              file=sys.stderr)
        return 2

    table = cells(legs)
    print('# foldpar: %d leg(s) read, %d refused%s' % (
        len(legs), refused,
        (' (' + ', '.join('%s x%d' % (k, v) for k, v in sorted(reasons.items())) + ')')
        if refused else ''))
    print('# eff = (cpu/wall)/threads. Min over reps BY WALL; spread is max/min-1 across reps.')

    if as_csv:
        print('label,affinity,threads,arm,budget,m,wall_s,cpu_s,P,eff,peak_mb,reps,spread_pct')
        for key in sorted(table):
            c = table[key]
            print('%s,%s,%d,%s,%s,%d,%.3f,%.3f,%.3f,%.4f,%.1f,%d,%.2f' % (
                key[0], key[1], key[2], key[3], key[4], key[5],
                c['wall'], c['cpu'], c['P'], c['eff'], c['peak_mb'], c['reps'],
                c['spread_pct']))
        return 0

    hdr = '%-14s %-9s %3s %-6s %-6s %5s %9s %10s %7s %6s %8s %6s' % (
        'label', 'affinity', 't', 'arm', 'budget', 'm', 'wall_s', 'cpu_s',
        'cpu/wall', 'eff', 'peak_mb', 'sprd%')
    print()
    print(hdr)
    print('-' * len(hdr))
    for key in sorted(table):
        c = table[key]
        print('%-14s %-9s %3d %-6s %-6s %5d %9.3f %10.3f %7.3f %6.3f %8.1f %6.2f' % (
            key[0], key[1], key[2], key[3], key[4], key[5],
            c['wall'], c['cpu'], c['P'], c['eff'], c['peak_mb'], c['spread_pct']))

    # ---- the verdict block: the fold's eff against the pool, and the
    # class-neutral fold/force ratio at the same cell.
    print()
    print('VERDICT BLOCK - the fold\'s effective parallelism against the pool,')
    print('and the fold/force ratio at the same rung, which cancels core class.')
    print('A fold eff that FALLS as the pool widens while force\'s HOLDS is the')
    print('banked i5 shape; the two tracking each other is its refutation.')
    groups = sorted({(k[0], k[1]) for k in table})
    for label, aff in groups:
        pools = sorted({k[2] for k in table if k[0] == label and k[1] == aff})
        ms = sorted({k[5] for k in table if k[0] == label and k[1] == aff})
        print()
        print('  %s / affinity=%s' % (label, aff))
        head = '    %-16s' % 'cell' + ''.join('%12s' % ('m=%d' % m) for m in ms)
        print(head)
        for arm, budget, name in (('fold', 'big', 'fold eff'),
                                  ('force', 'big', 'force(res) eff'),
                                  ('force', '2048', 'force(win) eff')):
            for t in pools:
                row = []
                for m in ms:
                    c = table.get((label, aff, t, arm, budget, m))
                    row.append('%12s' % ('%.3f' % c['eff'] if c else '-'))
                print('    %-16s%s' % ('%s t%d' % (name, t), ''.join(row)))
        print('    %-16s' % 'fold/force(res)' + ''.join('%12s' % '' for _ in ms))
        for t in pools:
            row = []
            for m in ms:
                f = table.get((label, aff, t, 'fold', 'big', m))
                g = table.get((label, aff, t, 'force', 'big', m))
                row.append('%12s' % ('%.3f' % (f['eff'] / g['eff'])
                                     if f and g and g['eff'] else '-'))
            print('    %-16s%s' % ('  ratio t%d' % t, ''.join(row)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
