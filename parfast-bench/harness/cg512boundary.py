#!/usr/bin/env python3
"""cg512boundary.py - read cg512.py legs per slab boundary: what dirty pages
a spilled repair carries across each spill write, and into the next slab's feed.

Written for claim parfast-spill-per-slab-flush-15sep (the addendum of
an internal note), so the next lane
over the same traces does not rebuild it a third time (the m192 lane's
boundary.py and this lane's first cut both lived only in session scratch).

INPUT: one or more cg512.py OUT jsonl files, each beside the `legs/` directory
the same run wrote (cg512.py puts both under its R):

    cg512boundary.py R1/p1.jsonl R2/p1.jsonl --cells

A leg is read from its own `legs/<tag>.err` (NZBFAST_REPAIR_TIMING lines plus
NZBFAST_MEM_FLOOR_SERIES stamps, so run cg512.py with SERIES_ALL=1) and
`legs/<tag>.samp` (the 25 ms trace). Python 3.8 is enough.

THE WINDOWS. A slab's solve ends with `back-substitution (...)`; `put_slab`
then writes the slab into the spill file; the next slab starts at `feed shape
under ...`, and the last slab's window ends at `patch:`. Only
`back-substitution (` opens a window: `back-substitution setup` must NOT, or
the window starts after the write it is meant to measure (the first cut made
exactly that mistake). Log lines carry no clock of their own, so each is
placed at the series stamp before it, and the series clock is offset to the
driver's by the first trace sample with anonymous memory.

PER BOUNDARY it reports, in MiB:
  sum    max over the window of anon + file_dirty + file_writeback + kernel,
         the part of the scope's charge reclaim cannot free without I/O
  anon   anon at that instant
  win    max of dirty + writeback inside the window (the write's own pages)
  next   max of dirty + writeback over the first 0.5 s of the next feed -
         what a per-slab flush is meant to leave at 0
  nsum   max of the non-reclaimable sum over that same 0.5 s

and per leg the `spill flush (<bytes> B): <time>` lines, if the binary logs
them. `--cells` adds one pooled line per (set, m, budget, arm, limit, TAG)
cell, where TAG is cg512.py's TAG env with any trailing `-r<N>` removed.
"""
import argparse
import collections
import json
import os
import re
import statistics

MIB = 1048576.0
UNIT = {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}
NEXT_FEED_S = 0.5


def windows(err):
    """[(t_open, t_close, label)] on the series clock."""
    out, t_last, open_at, n = [], 0.0, None, 0
    for ln in err.splitlines():
        m = re.search(r"mem-floor series: ([0-9.]+)s", ln)
        if m:
            t_last = float(m.group(1))
            continue
        if "back-substitution (" in ln:
            open_at = t_last
        elif open_at is not None and ("feed shape under" in ln or "repair-timing: patch:" in ln):
            n += 1
            out.append((open_at, t_last, "s%d->%s" % (n, "patch" if "patch:" in ln else n + 1)))
            open_at = None
    return out


def read_trace(path):
    rows = []
    with open(path) as f:
        next(f)
        for ln in f:
            t, _cur, a, _file, d, wb, k, _scan = ln.split()
            rows.append((float(t), int(a), int(d), int(wb), int(k)))
    return rows


def leg(rec, legs_dir):
    tag = rec["tag"]
    err = open(os.path.join(legs_dir, tag + ".err"), errors="replace").read()
    trace = read_trace(os.path.join(legs_dir, tag + ".samp"))
    off = next((t for t, a, *_ in trace if a > 0), 0.0)
    flushes = [float(v) * UNIT[u] for _, v, u in re.findall(r"spill flush \((\d+) B\): ([0-9.]+)(µs|ms|s)", err)]
    bnd = []
    for t0, t1, label in windows(err):
        seg = [s[1:] for s in trace if t0 + off - 0.05 <= s[0] <= t1 + off + 0.05]
        nxt = [s[1:] for s in trace if t1 + off <= s[0] <= t1 + off + NEXT_FEED_S]
        if not seg:
            continue
        best = max(seg, key=sum)
        bnd.append({
            "at": label,
            "sum": round(sum(best) / MIB),
            "anon": round(best[0] / MIB),
            "win": round(max(s[1] + s[2] for s in seg) / MIB),
            "next": round(max(s[1] + s[2] for s in nxt) / MIB) if nxt else None,
            "nsum": round(max(sum(s) for s in nxt) / MIB) if nxt else None,
        })
    tight = max((a + d + wb + k for _, a, d, wb, k in trace), default=0)
    return {"tight": round(tight / MIB, 1), "flushes": flushes, "boundaries": bnd}


def cell_tag(tag):
    """cg512.py names a leg <set>-m<m>-<budget>-<arm>-<limit>-r<rep>[-<TAG>];
    the pooled cell keeps TAG without a trailing -r<N>."""
    m = re.search(r"-r\d+-(.+)$", tag)
    return re.sub(r"-r\d+$", "", m.group(1)) if m else ""


def main():
    ap = argparse.ArgumentParser(description="per slab boundary dirty pages from cg512.py legs")
    ap.add_argument("jsonl", nargs="+", help="cg512.py OUT files, each beside its legs/")
    ap.add_argument("--cells", action="store_true", help="also print one pooled line per cell")
    args = ap.parse_args()
    cells = collections.OrderedDict()
    for path in args.jsonl:
        legs_dir = os.path.join(os.path.dirname(os.path.abspath(path)), "legs")
        with open(path) as f:
            recs = [json.loads(line) for line in f if line.strip()]
        for rec in recs:
            got = leg(rec, legs_dir)
            fl = got["flushes"]
            print("%-44s ok=%s oom_kill=%s wall=%.2f anon=%.1f tight=%.1f slabs=%d flushes=%d (sum %.2fs, max %.2fs)"
                  % (rec["tag"], rec["ok"], rec["oom_kill"], rec["wall"], rec["samp_anon_max_mib"], got["tight"],
                     rec["slabs"], len(fl), sum(fl), max(fl, default=0.0)))
            for b in got["boundaries"]:
                print("    %-10s sum %4s  anon %4s  win %3s  next %4s  nsum %4s" % (
                    b["at"], b["sum"], b["anon"], b["win"], b["next"], b["nsum"]))
            key = (rec["set"], rec["m"], rec["budget"], rec["arm"], rec["limit"] or "free", cell_tag(rec["tag"]))
            c = cells.setdefault(key, {"legs": [], "bnd": [], "fl": []})
            c["legs"].append((rec, got))
            c["bnd"] += got["boundaries"]
            c["fl"] += fl
    if not args.cells:
        return
    print()
    for key, c in cells.items():
        recs = [r for r, _ in c["legs"]]
        nz = [b for b in c["bnd"] if b["next"]]
        print("%s legs=%d ok=%d kills=%d anon=%.0f-%.0f tight=%.0f-%.0f wall med %.2f | boundaries %d, next-feed dirty on %d (max %s) | win max %s | flushes %d%s" % (
            key, len(recs), sum(1 for r in recs if r["ok"]), sum(1 for r in recs if r["oom_kill"]),
            min(r["samp_anon_max_mib"] for r in recs), max(r["samp_anon_max_mib"] for r in recs),
            min(g["tight"] for _, g in c["legs"]), max(g["tight"] for _, g in c["legs"]),
            statistics.median(r["wall"] for r in recs),
            len(c["bnd"]), len(nz), max((b["next"] for b in nz), default=0),
            max((b["win"] for b in c["bnd"]), default=None), len(c["fl"]),
            (" %.0f-%.0f ms" % (min(c["fl"]) * 1000, max(c["fl"]) * 1000)) if c["fl"] else ""))


if __name__ == "__main__":
    main()
