#!/usr/bin/env python3
"""Does the full-box non-monotonicity generalise beyond the pinned round? NO.

Written 17 Sep 2026 for lane `parfast-4mib-pinned-affinity-pools`, to test a
claim that lane had just LANDED and to correct it. A row gate is a ratio of fold
to force and CANNOT fall as m rises, so a non-monotone F/T is a fact about the
instrument rather than about the gate, and it is a cheap, box-free screen over
every ladder this repo has banked.

WHAT IT FOUND, run over every log under rounds/ carrying a
`threads=16` leg: **4 non-monotone of 36 full-box tables against 5 of 29 sub-box
ones** - if anything the wrong way round. THREE of the four full-box failures
are that lane's own `4m-t16` arm and the fourth is a round whose foreign CPU ran
at a median of 84% of a core. So the section's first draft, which said a
full-box ladder on this part is not a measurement and a sub-box one is, was too
wide by a lot, and the surviving claim is about ONE ARM AT ONE SHAPE (4 MiB,
n = 4,096, resident, sixteen threads) rather than about core count.

RUN:  ladder-monotonicity-audit.py $(grep -rl 'threads=16' rounds/)

It is a SCREEN, not a gate: a non-monotone table with a high A/A floor is the
instrument declaring its own noise, which is the system working. Read the floor
column beside the verdict, and never treat a hit as a defect on its own.
"""
import re, subprocess, sys, glob, os

tbl  = re.compile(r'^== (\S+) threads=(\d+)')
row  = re.compile(r'^\s*(\d+) \|\s*[\d.]+\s+[\d.]+\s+([\d.]+) \|\s*[\d.]+%\s+[\d.]+%\s+([\d.]+)%')

files = sorted(set(sys.argv[1:]))
out_rows = []
for lg in files:
    try:
        out = subprocess.run(['python3','harness/rowgate.py','read',lg],
                             capture_output=True, text=True, timeout=180).stdout
    except Exception:
        continue
    cur = None
    for ln in out.splitlines():
        m = tbl.match(ln)
        if m:
            if cur and len(cur['ft']) >= 3: out_rows.append(cur)
            cur = {'log': lg, 'label': m.group(1), 'thr': int(m.group(2)), 'ft': [], 'fl': []}
            continue
        r = row.match(ln)
        if r and cur is not None:
            cur['ft'].append(float(r.group(2))); cur['fl'].append(float(r.group(3)))
    if cur and len(cur['ft']) >= 3: out_rows.append(cur)

print(f"{'thr':>4} {'label':<22}{'mono':<6}{'worst floor':>12}  log")
print("-"*110)
bad16 = bad_other = tot16 = tot_other = 0
for r in sorted(out_rows, key=lambda x: (-x['thr'], x['log'])):
    mono = all(b >= a for a, b in zip(r['ft'], r['ft'][1:]))
    full = r['thr'] >= 16
    if full:
        tot16 += 1;    bad16 += (not mono)
    else:
        tot_other += 1; bad_other += (not mono)
    if not mono:
        print(f"{r['thr']:>4} {r['label']:<22}{'NO':<6}{max(r['fl']):>11.1f}%  {os.path.relpath(r['log'])}")
print("-"*110)
print(f"full-box (threads>=16) ladders: {tot16:3d}   non-monotone: {bad16:3d}"
      + (f"  ({100*bad16/tot16:.0f}%)" if tot16 else ""))
print(f"sub-box  (threads< 16) ladders: {tot_other:3d}   non-monotone: {bad_other:3d}"
      + (f"  ({100*bad_other/tot_other:.0f}%)" if tot_other else ""))
