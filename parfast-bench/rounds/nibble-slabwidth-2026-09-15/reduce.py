#!/usr/bin/env python3
"""reduce.py ROUND.jsonl LEGDIR [MAXLOAD] - per (m, arm) medians for the slab-width round.

From each leg's .err: slab count / width, total NTT transform seconds (sum of
`ntt syndromes` lines), windows per slab, slices per full window, the W on the
syndromes line, solve seconds (back-substitution), feed+fold+solve per slab,
stripe, peak ru_maxrss (the mem-floor line; the jsonl column is also KiB-true now).
A leg whose start or end 1-min load exceeds MAXLOAD (default 6 on 12 cores,
where the leg itself contributes ~t) or whose foreign CPU averages over
1.5 cores for its wall (idle baseline 0.70) is dropped and listed.
"""
import json, re, statistics, sys
from collections import defaultdict

def secs(v, u):
    return float(v) * {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}[u]

rows = [json.loads(l) for l in open(sys.argv[1])]
legdir = sys.argv[2]
maxload = float(sys.argv[3]) if len(sys.argv) > 3 else 6.0
groups, dropped = defaultdict(list), []
for r in rows:
    tag = "m%d-%s-%s-r%d" % (r["m"], r["path"], r["arm"], r["rep"])
    err = open("%s/%s.err" % (legdir, tag), errors="replace").read()
    ntt = [(int(n), int(w), secs(v, u)) for n, w, v, u in
           re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=(\d+), W=(\d+), threads=\d+\): ([0-9.]+)(µs|ms|s)", err)]
    wins = [(int(b), int(s)) for b, s in re.findall(r"ntt window \((\d+) bytes, (\d+) slices, transformed\)", err)]
    bs = [secs(v, u) for v, u in re.findall(r"back-substitution \([^)]*\): ([0-9.]+)(µs|ms|s)", err)]
    ffs = [secs(v, u) for v, u in re.findall(r"feed\+fold\+solve: \+([0-9.]+)(µs|ms|s)", err)]
    scan = re.search(r"verify targets \+ volume scan: \+([0-9.]+)(µs|ms|s)", err)
    rss = re.search(r"mem-floor: live high-water · ru_maxrss (\d+) MB", err)
    folded = len(re.findall(r"folded\)", err))
    r.update(ntt_s=sum(x[2] for x in ntt), ntt_calls=len(ntt), W=sorted({x[1] for x in ntt}),
             win_slices=max((s for _, s in wins), default=max((x[0] for x in ntt), default=0)),
             solve_s=sum(bs), ffs_s=ffs, scan_s=secs(*scan.groups()) if scan else None,
             rss=int(rss.group(1)) if rss else None, folded=folded)
    load_hi = max(r["load"])
    fc = r.get("foreign_cpu_s")
    # The idle box burns ~0.70 CPU-s/s (smbd), measured before the round;
    # a leg is dropped only when foreign CPU averages over 1.5 cores.
    if not r["ok"] or load_hi > maxload or (fc is not None and fc > 1.5 * r["wall"]):
        dropped.append((tag, r["ok"], r["load"], fc))
        continue
    groups[(r["m"], r["arm"])].append(r)

med = lambda xs: statistics.median(xs) if xs else float("nan")
print("| m | arm | argv | slabs x width | windows / slab, slices / window, W | stripe | wall med (reps) | CPU-s med | NTT s med | NTT s per slab | solve s | rest s | ru_maxrss MB | load | foreign CPU-s |")
print("|---:|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|---|")
for (m, arm), rs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1].endswith("-t1"), kv[0][1])):
    r0 = rs[0]
    wall = med([r["wall"] for r in rs])
    ntt = med([r["ntt_s"] for r in rs])
    solve = med([r["solve_s"] for r in rs])
    print("| %d | %s | `%s` | %d x %d | %.1f, %d, %s | %s | **%.2f** (%s) | %.1f | **%.2f** | %.2f | %.2f | %.2f | %s | %s | %s |" % (
        m, arm, " ".join(r0["argv"][1:-1]), r0["slabs"], r0["slab_width"],
        r0["ntt_calls"] / r0["slabs"], r0["win_slices"], "/".join(map(str, r0["W"])),
        ",".join("%dw" % w for w in r0["stripe_w"]) or "-",
        wall, " / ".join("%.2f" % r["wall"] for r in rs), med([r["cpu"] for r in rs]),
        ntt, ntt / r0["slabs"], solve, wall - ntt - solve,
        " / ".join(str(r["rss"]) for r in rs),
        " ".join("%.1f-%.1f" % tuple(r["load"]) for r in rs),
        " / ".join(str(r.get("foreign_cpu_s")) for r in rs)))
    if any(r["folded"] for r in rs):
        print("  (FOLDED windows present in", arm, ")")
print()
for d in dropped:
    print("DROPPED", d)
