#!/usr/bin/env python3
"""Best-of-N table from LEG lines. Any round that failed its content gate
disqualifies the tool for that shape: a wrong answer is not a fast time."""
import sys, collections

TOOLS = ["ours", "unrar", "rarpar", "unar", "bsdtar", "7zz"]
SHAPES = ["store", "small", "solid", "rep", "big", "enc", "r7dict"]
INSTRUMENT_KEYS = {"warm", "pos", "gap_ms", "warm_ms", "fp_ms", "tear_ms"}

times = collections.defaultdict(list)
notes = {}
for path in sys.argv[1:]:
    for line in open(path):
        if not line.startswith("LEG "):
            continue
        f = line.split()
        shape, tool, _round, secs, verdict = f[1], f[2], f[3], f[4], f[5]
        if verdict == "ok":
            times[(shape, tool)].append(float(secs))
        else:
            # The harness appends its own instrumentation after the verdict
            # (warm=, pos=, gap_ms=, ...); strip exactly those, from the end,
            # so a verdict string that happens to contain "=" survives.
            tail = f[5:]
            while tail and tail[-1].split("=")[0] in INSTRUMENT_KEYS:
                tail.pop()
            notes[(shape, tool)] = " ".join(tail)

print(f"{'shape':<8}" + "".join(f"{t:>12}" for t in TOOLS))
for sh in SHAPES:
    row = f"{sh:<8}"
    best = {}
    for t in TOOLS:
        v = times.get((sh, t))
        best[t] = min(v) if v else None
    win = min((v for v in best.values() if v is not None), default=None)
    for t in TOOLS:
        if best[t] is None:
            row += f"{'--':>12}"
        else:
            mark = "*" if best[t] == win else " "
            row += f"{best[t]:>11.3f}{mark}"
    print(row)
print()
for (sh, t), n in sorted(notes.items()):
    if times.get((sh, t)):
        continue
    print(f"  {sh:<8} {t:<8} {n}")
