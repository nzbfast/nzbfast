#!/usr/bin/env python3
"""nibask.py - reduce the nibble windowed-ask round (wcomb.ps1 validate, `inb` arm).

    rounds/ntt-nibble-ask-2026-09-15/nibask.py LOG [LOG...]

Written 15 Sep 2026 for lane parfast-ntt-nibble-windowed-ask-15sep. Per
(block size, m): the fold and the in-budget forced transform (`inb`), each the
MINIMUM over its reps, with its A/A copy (`fold2`, `inb2`) reduced the same
way. A cell RESOLVES only when inb / fold clears both arms' own A/A spread
(|a - a2| / min(a, a2)); the pooled figure takes each arm's best of both
copies. `auto` is printed with the path it took and, where it transformed,
whether `inb` ran the same W and windows - the check that makes `inb` the
admission `auto` would have given it.

Refuses a leg whose rc is not 0 or whose SHA gate did not restore 16/16.
"""
import statistics
import sys


def legs(paths):
    for p in paths:
        for line in open(p, encoding="utf-8", errors="replace"):
            line = line.strip().lstrip("﻿")
            # harness-rig-gate: a reducer: it reads the LEG lines of a banked
            #   round and reports them. It banks no round log of its own.
            if line.startswith("LEG "):
                kv = dict(t.split("=", 1) for t in line.split()[1:] if "=" in t)
                if kv["rc"] != "0" or kv["restored"] != "16/16":
                    sys.exit("refused: %s rc=%s restored=%s" % (kv["round"], kv["rc"], kv["restored"]))
                yield kv


def main(paths):
    rows = list(legs(paths))
    by = {}
    for r in rows:
        by.setdefault((int(r["slice"]), int(r["m"]), r["arm"]), []).append(r)
    foreign = [float(r["foreign_cpu"]) for r in rows if r["foreign_cpu"]]
    print("%d legs, all rc 0 and 16/16; foreign CPU %% of one core per leg: median %.0f, p90 %.0f, max %.0f"
          % (len(rows), statistics.median(foreign), sorted(foreign)[int(0.9 * (len(foreign) - 1))], max(foreign)))
    print("%-7s %4s | %6s %6s %5s | %6s %6s %5s | %6s %6s %-10s | %6s %-9s | %s" % (
        "block", "m", "fold", "fold2", "A/A", "inb", "inb2", "A/A", "auto", "path", "W x win", "inb/fd", "resolved", "inb W x windows, peak MB"))
    for bs, m in sorted({(k[0], k[1]) for k in by}):
        def best(arm):
            c = by.get((bs, m, arm))
            return min(c, key=lambda r: float(r["cpu"])) if c else None
        f, f2, i, i2, a = (best(x) for x in ("fold", "fold2", "inb", "inb2", "auto"))
        cpu = lambda r: float(r["cpu"]) if r else float("nan")
        spread = lambda x, y: abs(cpu(x) - cpu(y)) / min(cpu(x), cpu(y)) if x and y else float("nan")
        fb, ib = min(cpu(f), cpu(f2)), min(cpu(i), cpu(i2))
        ratio = ib / fb
        floor = max(spread(f, f2), spread(i, i2))
        verdict = ("inb wins" if ratio < 1 else "fold wins") if abs(1 - ratio) > floor else "unresolved"
        aw = "W%s x %s" % (a["ntt_w"], a["windows"]) if a and a["path"] == "ntt" else "-"
        match = ""
        if a and a["path"] == "ntt" and i:
            match = " (same as auto)" if (a["ntt_w"], a["windows"], a["win_slices"]) == (i["ntt_w"], i["windows"], i["win_slices"]) else " (DIFFERS from auto)"
        print("%-7s %4d | %6.2f %6.2f %4.1f%% | %6.2f %6.2f %4.1f%% | %6.2f %6s %-10s | %6.3f %-9s | W%s x %s of %s, %s%s" % (
            "%dK" % (bs // 1024), m, cpu(f), cpu(f2), 100 * spread(f, f2), cpu(i), cpu(i2), 100 * spread(i, i2),
            cpu(a), a["path"] if a else "-", aw, ratio, verdict,
            i["ntt_w"] if i else "-", i["windows"] if i else "-", i["win_slices"].split("/")[0] if i else "-",
            i["peak_mb"] if i else "-", match))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
