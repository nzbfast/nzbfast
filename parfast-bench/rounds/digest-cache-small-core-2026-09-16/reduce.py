#!/usr/bin/env python3
"""Reduce dcsmall/dcladder LEG lines to a per-arm table."""
import re, sys, statistics

def parse(path):
    legs = []
    for line in open(path, errors='replace'):
        if not line.startswith('LEG '):
            continue
        d = dict(re.findall(r'(\w+)=([^\s\[]+|\[[^\]]*\])', line))
        d['wall'] = float(d['wall'])
        legs.append(d)
    return legs

def main():
    for path in sys.argv[1:]:
        legs = parse(path)
        print("=== %s  (%d legs)" % (path, len(legs)))
        shas = set(l.get('sha') for l in legs)
        print("    set sha(s): %s" % ", ".join(sorted(shas)))
        keys = []
        for l in legs:
            k = (l['arm'], l.get('t', '-'))
            if k not in keys:
                keys.append(k)
        med = {}
        for k in keys:
            walls = [l['wall'] for l in legs if (l['arm'], l.get('t','-')) == k]
            med[k] = statistics.median(walls)
            dcs = set(l.get('dc','-') for l in legs if (l['arm'], l.get('t','-')) == k)
            fc = [float(l['foreign_cpu']) for l in legs if (l['arm'], l.get('t','-')) == k]
            print("  arm=%-6s t=%-3s reps=%d walls=%s median=%.2f foreign=%s dc=%s"
                  % (k[0], k[1], len(walls), walls, med[k], [round(x,1) for x in fc], "; ".join(sorted(dcs))))
        ts = sorted(set(k[1] for k in keys), key=lambda s: -int(s) if s != '-' else 0)
        for t in ts:
            f = med.get(('fresh', t)); h = med.get(('hit', t)); e = med.get(('enrol', t))
            if f and h:
                print("  RATIO t=%-3s hit/fresh=%.3f  %s 0.55x gate%s"
                      % (t, h/f, "CLEARS" if h/f <= 0.55 else "MISSES",
                         "" if e is None else "   enrol/fresh=%.3f (%+.1f%%)" % (e/f, (e/f-1)*100)))
main()
