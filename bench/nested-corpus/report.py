#!/usr/bin/env python3
"""report.py - turn a round's suite.log into the write-up tables.

    report.py <suite.log> [--not-scored LEG,LEG]

Reads the LEG lines and prints the completion-class table, the per-leg
wall/disk/RSS/CPU table, and the totals - with the two rules an earlier
round had to state in prose and could not enforce:

  * A DISK OR WALL TOTAL IS ONLY MEANINGFUL OVER A COMPLETED SUBSET.
    One client's total was the SMALLEST of five in an earlier round and it
    completed nothing; another's wall, excluding the leg where it waits for
    an operator, came in below ours while it finished three fewer legs than
    it was being compared on. So every total here is printed beside the
    number of legs it covers and the count of those that auto-completed,
    and the like-for-like table is restricted to legs EVERY listed client
    auto-completed.
  * A CELL FROM AN UNDER-SAMPLED LEG IS MARKED, never silently averaged.

--not-scored NAMES keeps a leg in every table but out of the auto count.
A leg can be evidence without being a capability score: the depth-10
ladder is a POLICY cell - we finish it with the depth cap raised and grade
manual at the shipped default - so counting it scores a configuration
choice rather than an ability, in a row where no other client is close
either. Excluded legs are printed under the table by name, so a reader is
told what was left out rather than having to notice a count that does not
add up.
"""

import re
import sys
from collections import defaultdict

def parse(path):
    rows = []
    for line in open(path):
        if not line.startswith("LEG "):
            continue
        parts = line.split()
        leg, client = parts[1], parts[2]
        # FIND, NEVER DICT. A `LEG` line's key=value fields are not
        # guaranteed unique: the provider rig's report() adds a `WARN=` on
        # every shaped leg and rig-lib's guard 7 adds one PER CAPPED HOST,
        # so a shaped leg legitimately carries three on one line. This rig
        # emits no WARN today, which is exactly why the next reader copied
        # from here would be silently wrong the day it is pointed at a leg
        # log that does - and the field it would drop is the one that
        # exists to stop a contaminated `gbytes` being published. So
        # repeated keys accumulate into a list rather than collapsing to
        # the first or the last of them.
        kv = {}
        for p in parts[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                if k in kv:
                    kv[k] = (kv[k] if isinstance(kv[k], list) else [kv[k]]) + [v]
                else:
                    kv[k] = v
        rows.append({"leg": leg, "client": client, **kv})
    return rows

def num(v, default=None):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default

def main():
    argv = sys.argv[1:]
    not_scored = set()
    if "--not-scored" in argv:
        i = argv.index("--not-scored")
        not_scored = {x for x in argv[i + 1].split(",") if x}
        del argv[i:i + 2]
    rows = parse(argv[0])
    clients, legs = [], []
    for r in rows:
        if r["client"] not in clients:
            clients.append(r["client"])
        if r["leg"] not in legs:
            legs.append(r["leg"])
    by = {(r["leg"], r["client"]): r for r in rows}

    print("== completion class ==")
    hdr = "| leg | " + " | ".join(clients) + " |"
    print(hdr); print("|" + "---|" * (len(clients) + 1))
    autos = defaultdict(int)
    for leg in legs:
        cells = []
        for c in clients:
            r = by.get((leg, c))
            if not r:
                cells.append("-"); continue
            cls = r.get("class", "?")
            m = r.get("matched", "")
            short = {"auto-complete": "auto", "manual-intervention": "manual",
                     "fail": "fail", "hung": "hung"}.get(cls, cls)
            if cls == "auto-complete" and leg not in not_scored:
                autos[c] += 1
            cells.append(short + (" " + m if m and "/" in m and not m.endswith("/1") else ""))
        print("| %s | %s |" % (leg, " | ".join(cells)))
    scored = [l for l in legs if l not in not_scored]
    print("| **auto count** | " + " | ".join("**%d/%d**" % (autos[c], len(scored)) for c in clients) + " |")
    for l in legs:
        if l in not_scored:
            print("  (not scored, shown as evidence only: %s)" % l)

    print()
    print("== per-leg wall_s / hiwater_mb / peak_rss_mb / cpu_s ==")
    print("(a cell marked * is under-sampled: the leg was shorter than the sampler's own cadence)")
    print(hdr); print("|" + "---|" * (len(clients) + 1))
    for leg in legs:
        cells = []
        for c in clients:
            r = by.get((leg, c))
            if not r:
                cells.append("-"); continue
            du = "*" if r.get("disk_undersampled") == "yes" else ""
            pu = "*" if r.get("ps_undersampled") == "yes" else ""
            cells.append("%ss / %s%s MB / %s%s MB / %s%s" % (
                r.get("wall_s", "?"), r.get("hiwater_mb", "?"), du,
                r.get("rss_mb", "?"), pu, r.get("cpu_s", "?"), pu))
        print("| %s | %s |" % (leg, " | ".join(cells)))

    print()
    print("== totals, each beside the subset it covers ==")
    print("| client | legs | auto | wall_s total | disk total MB | disk total over AUTO legs only |")
    print("|---|---:|---:|---:|---:|---:|")
    for c in clients:
        rs = [by[(l, c)] for l in scored if (l, c) in by]
        w = sum(num(r.get("wall_s"), 0) for r in rs)
        d = sum(num(r.get("hiwater_mb"), 0) for r in rs)
        da = sum(num(r.get("hiwater_mb"), 0) for r in rs if r.get("class") == "auto-complete")
        print("| %s | %d | %d | %d | %d | %d |" % (c, len(rs), autos[c], w, d, da))

    # Like-for-like: only legs EVERY client auto-completed.
    common = [l for l in scored
              if all(by.get((l, c), {}).get("class") == "auto-complete" for c in clients)]
    print()
    if common:
        print("== like-for-like: the %d leg(s) EVERY client auto-completed ==" % len(common))
        print("  " + ", ".join(common))
        print("| client | disk high-water MB | peak RSS MB | cpu_s | vs nzbfast disk |")
        print("|---|---:|---:|---:|---:|")
        base = None
        for c in clients:
            d = sum(num(by[(l, c)].get("hiwater_mb"), 0) for l in common)
            m = max([num(by[(l, c)].get("rss_mb"), 0) for l in common] or [0])
            cp = sum(num(by[(l, c)].get("cpu_s"), 0) for l in common)
            if base is None:
                base = d
            rel = "-" if c == clients[0] else ("%+.0f%%" % (100 * (d - base) / base) if base else "n/a")
            print("| %s | %d | %d | %.1f | %s |" % (c, d, m, cp, rel))
    else:
        print("== like-for-like: NO leg was auto-completed by every client ==")
        print("  So there is no all-client disk comparison in this round, and any")
        print("  total above is over a DIFFERENT subset of work per client.")
        # Fall back to the largest client subset that shares auto legs.
        for c in clients:
            got = [l for l in scored if by.get((l, c), {}).get("class") == "auto-complete"]
            print("  %-16s auto on: %s" % (c, ", ".join(got) if got else "(none)"))

if __name__ == "__main__":
    main()
