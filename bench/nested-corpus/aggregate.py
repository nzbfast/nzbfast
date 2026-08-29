#!/usr/bin/env python3
"""aggregate.py - combine repeated passes of a round into one figure per cell.

    aggregate.py --runs DIR [DIR...] [--json OUT]

WHY REPEATS AT ALL, and why the median. Elapsed time on this rig is noisy in
a way the other measures are not: repeating one leg five times at constant
load gave a 25% spread, while its processor seconds read identically every
time. Measured on the same leg, adding twelve cpu hogs to a 32-core box
moved the median by -1.1%, so that spread is intrinsic to the leg rather
than contributed by neighbouring work, and a quiet machine would not remove
it. What a noisy quantity needs is repetition, so every timing here is the
MEDIAN of independent whole passes and the observed range is carried
alongside it rather than discarded.

Whole passes, never back-to-back repeats of one leg, so no repeat inherits
the previous one's warm caches.

Completion class is NOT averaged. A client either delivered the payload or
it did not, and a cell that disagrees between passes is reported as
disagreeing rather than smoothed into a majority - that would hide exactly
the intermittent failure a reader most needs to know about.
"""

import argparse
import json
import os
import statistics as st

NUM = ("wall_s", "hiwater_mb", "rss_mb", "cpu_s", "rd_mb", "wr_mb", "load")
OPNUM = ("op_wall_s", "op_hiwater_mb", "op_rd_mb", "op_wr_mb", "op_cpu_s", "passes")


def parse(path):
    legs, ops = {}, {}
    if not os.path.exists(path):
        return legs, ops
    for line in open(path):
        f = line.split()
        if not f:
            continue
        kv = {}
        for p in f[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                kv.setdefault(k, v)
        if f[0] == "LEG":
            legs[(f[1], f[2])] = kv
        elif f[0] == "OP":
            ops[(f[1], f[2])] = kv
    # The per-cell operator JSON is authoritative over the OP line, and a
    # `.rescoped` file wins over both: it is a re-run of a cell whose first
    # attempt was pointed at an empty delivery directory and therefore did
    # nothing at all, so its tree was still pristine and the second attempt
    # is a real first attempt rather than a second pass over extracted files.
    run = os.path.dirname(path)
    for (leg, client) in list(ops) + [k for k in ops]:
        for suffix, _ in (("json.rescoped", 1), ("json", 0)):
            j = os.path.join(run, leg, "op.%s.%s" % (client, suffix))
            if os.path.exists(j):
                try:
                    d = json.load(open(j))
                except Exception:
                    continue
                ops[(leg, client)] = {
                    "passes": d.get("passes"), "op_wall_s": d.get("total_seconds"),
                    "op_hiwater_mb": d.get("hiwater_mb"), "op_rd_mb": d.get("disk_read_mb"),
                    "op_wr_mb": d.get("disk_write_mb"), "op_cpu_s": d.get("cpu_s"),
                    "outcome": d.get("outcome"), "repairs": d.get("repairs"),
                    "rar_repairs": d.get("rar_repairs"), "extracts": d.get("extracts"),
                }
                break
    return legs, ops


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    allleg, allop = [], []
    for d in a.runs:
        l, o = parse(os.path.join(d, "suite.log"))
        allleg.append(l)
        allop.append(o)

    keys = sorted({k for l in allleg for k in l})
    out = {}
    for key in keys:
        leg, client = key
        cell = {"leg": leg, "client": client, "passes_seen": 0}
        classes = []
        for l in allleg:
            if key in l:
                cell["passes_seen"] += 1
                classes.append(l[key].get("class", "?"))
        cell["class"] = classes[0] if len(set(classes)) == 1 else "DISAGREES:" + "/".join(sorted(set(classes)))
        cell["class_stable"] = len(set(classes)) == 1
        cell["matched"] = next((l[key].get("matched", "") for l in allleg if key in l), "")
        for f in NUM:
            vals = [num(l[key].get(f)) for l in allleg if key in l]
            vals = [v for v in vals if v is not None]
            if vals:
                cell[f] = round(st.median(vals), 3)
                cell[f + "_min"] = round(min(vals), 3)
                cell[f + "_max"] = round(max(vals), 3)
                cell[f + "_n"] = len(vals)
        for f in OPNUM:
            vals = [num(o[key].get(f)) for o in allop if key in o]
            vals = [v for v in vals if v is not None]
            if vals:
                cell[f] = round(st.median(vals), 3)
                cell[f + "_min"] = round(min(vals), 3)
                cell[f + "_max"] = round(max(vals), 3)
        oc = [o[key].get("outcome") for o in allop if key in o]
        cell["op_outcome"] = oc[0] if oc and len(set(oc)) == 1 else ("/".join(sorted(set(oc))) if oc else "")
        # The figures the report leads on: what the whole job cost, counting
        # the manual work a client left to be done.
        cell["total_wall_s"] = round(cell.get("wall_s", 0) + cell.get("op_wall_s", 0), 2)
        cell["total_wr_mb"] = round(cell.get("wr_mb", 0) + cell.get("op_wr_mb", 0), 1)
        cell["total_cpu_s"] = round(cell.get("cpu_s", 0) + cell.get("op_cpu_s", 0), 1)
        cell["peak_disk_mb"] = max(cell.get("hiwater_mb", 0), cell.get("op_hiwater_mb", 0))
        out[leg + "|" + client] = cell

    res = {"runs": a.runs, "cells": out}
    s = json.dumps(res, indent=1, sort_keys=True)
    if a.json:
        open(a.json, "w").write(s)
    unstable = [k for k, v in out.items() if not v["class_stable"]]
    print("aggregated %d cells over %d run(s); %d disagree across passes%s"
          % (len(out), len(a.runs), len(unstable),
             (": " + ", ".join(unstable)) if unstable else ""))


if __name__ == "__main__":
    main()
