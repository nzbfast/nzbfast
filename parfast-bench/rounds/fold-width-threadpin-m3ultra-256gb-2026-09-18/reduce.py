#!/usr/bin/env python3
"""Reduce this round's revscan-ab logs into the tables the write-up quotes.

DERIVED, NOT TYPED. Every figure in the dated section of
an internal note that names a
cell of this round comes out of here, so a log re-read cannot silently
disagree with the prose.

It also carries the round's own QUALITY GATE, which is not a formatting
nicety: a cell whose base or new arm has a wall SPAN wider than `--span-pct`
(default 25%) of its own median saw a foreign burst mid-cell, and its MEDIAN
ratio is not a figure. Two cells of round 1 are exactly that - P2 r1's PIN32
w3 (base span 179.9-331.5, 84%) and its PIN20 w2 (179.7-276.1, 54%) - and the
first is the one that reads 0.874 against 0.971 and 0.974 in the rounds either
side of it. They are printed with a `!` and EXCLUDED from the per-rung means
rather than deleted: the rule this campaign runs on is that a cell whose
control did not hold is re-taken, and both were, in rounds 2 and 3.

WHY 25% AND NOT 5%. The span is max-minus-min over 64 runs, so ONE slow run
widens it while leaving the median untouched - at 5% the gate drops A/A cells
reading 1.000 and keeps nothing useful. The two real contaminants are at 54%
and 84% and every clean cell here is under 20%, so 25% sits in a wide empty
band rather than on a judgement call. It is deliberately conservative in the
other direction too: it also flags two cells (P2 r2's PIN32 w8 at 52%, P2 r3's
warm PIN20 w3 at 31%) whose medians AGREE with their own repeats, which costs
nothing because both rungs have other clean rounds behind them.

Usage:  ./reduce.py [--span-pct 5]
"""
import re, sys, glob, statistics, argparse

CELL = re.compile(r'^(P\d\w*-[^\s]+)\s+drop=')
ARM  = re.compile(r'^\s+(base|new)\s+median\s+([\d.]+) ms\s+min\s+([\d.]+)\s+span\s+([\d.]+)-([\d.]+)\s+process CPU\s+([\d.]+) ms')
RAT  = re.compile(r'^\s+new/base\s+median ([\d.]+)\s+min/min ([\d.]+)')

def parse(paths):
    out = []
    for p in sorted(paths):
        cur = None
        for line in open(p):
            m = CELL.match(line)
            if m:
                cur = {'log': p, 'label': m.group(1)}
                out.append(cur); continue
            if cur is None: continue
            m = ARM.match(line)
            if m:
                cur[m.group(1)] = dict(median=float(m.group(2)), min=float(m.group(3)),
                                       lo=float(m.group(4)), hi=float(m.group(5)),
                                       cpu=float(m.group(6)))
                continue
            m = RAT.match(line)
            if m:
                cur['ratio'] = float(m.group(1)); cur['minmin'] = float(m.group(2))
    return [c for c in out if 'ratio' in c and 'base' in c and 'new' in c]

def dirty(c, pct):
    for a in ('base', 'new'):
        d = c[a]
        if (d['hi'] - d['lo']) / d['median'] * 100.0 > pct:
            return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--span-pct', type=float, default=25.0)
    a = ap.parse_args()
    cells = parse(glob.glob('*.log'))
    if not cells:
        sys.exit('reduce: no cells parsed - failing to find is failing.')

    print(f'# {len(cells)} cells, span gate {a.span_pct}% of median\n')

    # every cell, in log order
    print('## Every cell')
    print('| log | cell | ratio | min/min | base CPU | new CPU | flag |')
    print('|---|---|---|---|---|---|---|')
    for c in cells:
        f = '!' if dirty(c, a.span_pct) else ''
        print(f"| {c['log']} | {c['label']} | {c['ratio']:.3f} | {c['minmin']:.3f} | "
              f"{c['base']['cpu']:.1f} | {c['new']['cpu']:.1f} | {f} |")

    # the width sweep, per pin and cache mode
    W = re.compile(r'-(cold|warm)-PIN(\d+)-floor-w1-vs-w(\d+)$')
    by = {}
    for c in cells:
        m = W.search(c['label'])
        if not m: continue
        by.setdefault((m.group(1), int(m.group(2)), int(m.group(3))), []).append(c)
    for mode in ('cold', 'warm'):
        rows = sorted({(p, w) for (md, p, w) in by if md == mode})
        if not rows: continue
        pins = sorted({p for p, _ in rows}, reverse=True)
        print(f'\n## The width sweep at the clamp-floor window, {mode}')
        print('| pieces | ' + ' | '.join(f'PIN{p} ratio (n) | PIN{p} CPU' for p in pins) + ' |')
        print('|---' * (1 + 2 * len(pins)) + '|')
        for w in sorted({w for _, w in rows}):
            cs = f'| {w} '
            for p in pins:
                g = [c for c in by.get((mode, p, w), []) if not dirty(c, a.span_pct)]
                if not g: cs += '| - | - '; continue
                r = statistics.mean(x['ratio'] for x in g)
                cpu = statistics.mean(x['new']['cpu'] for x in g)
                cs += f'| {r:.3f} ({len(g)}) | {cpu:.1f} '
            print(cs + '|')

    # the A/A controls, which are what licence the rest
    aa = [c for c in cells if '-AA-' in c['label'] and not dirty(c, a.span_pct)]
    if aa:
        rs = [c['ratio'] for c in aa]
        print(f'\n## A/A controls: {len(aa)} clean, range {min(rs):.3f}-{max(rs):.3f}')

if __name__ == '__main__':
    main()
