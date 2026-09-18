#!/usr/bin/env python3
"""mmsum.py - reduce a `mmbench.rs` round and its `dmem.py` tls cell to the
four numbers a memmove round is decided on. Written for the confirming round
of claim `memops-memmove-confirming-round-17sep`; the two earlier rounds of
an internal note were reduced by hand, which
is why this exists.

Two things here are the method rather than presentation, and both come from
that note:

  - **The primitive bench is reduced BY FAMILY, not as one population.** A
    memmove round changes four disjoint arms (self-move, short `n <= 32`,
    ascending overlap, descending overlap) plus a disjoint control that must
    NOT move, and a single "cells below parity" count folds a deliberate
    0.80x descending cell into the same number as an accidental one. The
    families are split on (gap, dir) exactly as `move_bytes` splits them.
  - **Every ratio is quoted beside the A/A**, which is the noise floor the
    same round measured; a cand/base figure inside the A/A spread is not a
    result. The tls ratios are PAIRED PER REP - arm order rotates per rep,
    so an unpaired mean is a measurement of the rotation.

    python3 mmsum.py membench3.txt [tls3.jsonl] [--desc-detail]
"""
import json
import sys
from collections import defaultdict

OVERLAP_SAFE_ANY_MAX = 32


def family(n, gap, dirn):
    """The arm `memops::move_bytes` actually takes, by its own predicates."""
    if gap == 0:
        return "self-move"
    if gap >= n or n <= OVERLAP_SAFE_ANY_MAX:
        return "disjoint/short" if gap >= n else "short n<=32"
    return "ascending" if dirn == "asc" else "descending"


def load_bench(path):
    """best-of across every round, per (arm, cell)."""
    best = defaultdict(lambda: float("inf"))
    cells = {}
    for line in open(path):
        if not line.startswith("CELL "):
            continue
        kv = dict(p.split("=", 1) for p in line.split()[1:])
        n, gap, dirn = int(kv["n"]), int(kv["gap"]), kv["dir"]
        key = (n, gap, dirn)
        cells[key] = family(n, gap, dirn)
        arm = kv["arm"]
        s = float(kv["s"])
        if s < best[(arm, key)]:
            best[(arm, key)] = s
    return best, cells


def bench_report(path, desc_detail=False):
    best, cells = load_bench(path)
    arms = sorted({a for a, _ in best})
    print("== membench %s: %d cells, arms %s ==" % (path, len(cells), arms))
    rows = defaultdict(list)
    for key, fam in cells.items():
        b = best[("base", key)]
        for arm in arms:
            if arm == "base":
                continue
            rows[(arm, fam)].append((b / best[(arm, key)], key))
    for arm in arms:
        if arm == "base":
            continue
        print("\n-- %s / base (>1 is faster than compiler_rt)" % arm)
        print("   %-16s %5s %8s %8s %8s   %s"
              % ("family", "cells", "min", "median", "max", "cells < 0.99"))
        for fam in ("self-move", "short n<=32", "ascending", "descending",
                    "disjoint/short"):
            v = sorted(rows[(arm, fam)])
            if not v:
                continue
            r = [x for x, _ in v]
            under = [(x, k) for x, k in v if x < 0.99]
            med = r[len(r) // 2]
            print("   %-16s %5d %8.3f %8.3f %8.3f   %d   worst %s"
                  % (fam, len(r), r[0], med, r[-1], len(under),
                     "-" if not under else "n=%d gap=%d %s at %.3f"
                     % (v[0][1][0], v[0][1][1], v[0][1][2], r[0])))
        allr = sorted(x for x, _ in sum((rows[(arm, f)] for f in
                      set(f for _, f in rows if _ == arm)), []))
        print("   %-16s %5d %8.3f %8.3f %8.3f   %d"
              % ("ALL", len(allr), allr[0], allr[len(allr) // 2], allr[-1],
                 sum(1 for x in allr if x < 0.99)))
        if desc_detail and arm == "cand":
            v = sorted(rows[(arm, "descending")])
            print("   descending cells below 0.99, worst first:")
            for x, k in v:
                if x >= 0.99:
                    break
                print("     n=%-8d gap=%-8d %.3f" % (k[0], k[1], x))


def tls_report(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    by = defaultdict(dict)
    for r in rows:
        by[r["rep"]][r["arm"]] = r
    print("\n== tls cell %s: %d legs, %d reps ==" % (path, len(rows), len(by)))
    bad = [r for r in rows if r["rc"] != 0]
    shas = {r["sha"] for r in rows if r.get("sha")}
    sizes = {r["bytes"] for r in rows}
    print("   rc!=0: %d   distinct output sha: %d   distinct byte counts: %s"
          % (len(bad), len(shas), sorted(sizes)))
    for metric in ("instructions", "cycles", "wall", "cpu"):
        print("   %-13s" % metric, end="")
        for arm in ("fast", "aa"):
            rs = []
            for rep, legs in sorted(by.items()):
                if arm in legs and "musl" in legs and legs[arm][metric]:
                    rs.append(legs[arm][metric] / legs["musl"][metric])
            if not rs:
                continue
            mean = sum(rs) / len(rs)
            print("  %s/musl %.4f (%.4f..%.4f)"
                  % (arm, mean, min(rs), max(rs)), end="")
        print()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    bench_report(args[0], "--desc-detail" in sys.argv)
    if len(args) > 1:
        tls_report(args[1])
