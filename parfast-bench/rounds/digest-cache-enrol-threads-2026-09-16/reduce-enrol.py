#!/usr/bin/env python3
"""Reduce dcenrol LEG lines to a per-rung table against the +2% enrol gate.

One row per `ENROL_THREADS` rung: the three walls, the median, the three
MIRRORED PAIRS against the fresh leg of the SAME rep (which is the reading
9b-3 and the small-core round both quote, because a pair shares its load),
and the enrolment's own finish time out of the timing line - the number that
says whether the enrolment is a passenger on the create or its pole.
"""
import re, statistics, sys


def parse(path):
    legs = []
    for line in open(path, errors="replace"):
        # harness-rig-gate: a reducer over the LEG lines of a banked dcenrol
        #   round. The drivers that bank those logs - dcenrol.sh and
        #   dcenrol.ps1 - carry the stamp.
        if not line.startswith("LEG "):
            continue
        d = dict(re.findall(r"(\w+)=([^\s\[]+|\[[^\]]*\])", line))
        d["wall"] = float(d["wall"])
        d["rep"] = int(d["rep"])
        legs.append(d)
    return legs


def enrolled_s(dc):
    m = re.search(r"enrolling \(([0-9.]+)s\)", dc or "")
    return float(m.group(1)) if m else None


def main():
    for path in sys.argv[1:]:
        legs = parse(path)
        print("=== %s  (%d legs)" % (path, len(legs)))
        shas = sorted({l.get("sha") for l in legs})
        print("    set sha(s): %s%s" % (", ".join(shas), "" if len(shas) == 1 else "   <-- VOID, legs disagree"))
        fresh = {l["rep"]: l["wall"] for l in legs if l["arm"] == "fresh"}
        print("    fresh: %s  median=%.3f  chain_alone=%s"
              % ([fresh[r] for r in sorted(fresh)], statistics.median(fresh.values()),
                 sorted({l["chain_alone"] for l in legs if l["arm"] == "fresh"})))
        arms = [a for a in dict.fromkeys(l["arm"] for l in legs) if a != "fresh"]
        for arm in arms:
            rows = sorted((l for l in legs if l["arm"] == arm), key=lambda l: l["rep"])
            walls = [l["wall"] for l in rows]
            pairs = [(l["wall"] / fresh[l["rep"]] - 1) * 100 for l in rows if l["rep"] in fresh]
            enr = [enrolled_s(l.get("dc")) for l in rows]
            chain = [l["chain_alone"] for l in rows]
            worst = max(pairs) if pairs else float("nan")
            print("  %-4s walls=%s median=%.3f  pairs=%s  worst=%+.2f%%  %s   enrolled_at=%s  chain_alone=%s"
                  % (arm, ["%.3f" % w for w in walls], statistics.median(walls),
                     ["%+.2f%%" % p for p in pairs], worst,
                     "INSIDE +2%" if worst <= 2.0 else "FAILS +2%",
                     enr, chain))


main()
