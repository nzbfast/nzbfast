#!/usr/bin/env python3
"""spillslowsum.py - reduce the throttled-disk spill-flush round (claim
parfast-spill-flush-throttled-disk-cgroup-15sep) out of cg512.py's jsonl.

INPUT: one or more cg512.py OUT files written by the spillslow runners, whose
TAG is `<arm>-<disk>-r<rep>`, with disk the io.max rung (`d160`, `d100`, or
`dnone` for an uncapped control). The limit is already a field, so the tag is
only read for arm and disk. TWO ROUND SHAPES are read, because the second
round is built differently from the first and the A/A pair moves with it:

  spillslow-15sep  three BINARIES: `main` (origin/main, no flush code at all),
                   `gated` (branch, gate decides), `off` (branch, forced off).
                   A/A pair = main vs off, which differ only by dead code.
  spillslow2-16sep ONE binary from current origin/main, three ENV arms:
                   `gated` (no env, the shipped gate), `off` (_FLUSH=0) and
                   `aa` (_FLUSH=0 on a byte copy). A/A pair = off vs aa, which
                   are the same bytes doing the same work - a strictly tighter
                   floor than round 1's, and the reason round 2 exists in this
                   shape at all.

The A/A pair is chosen per cell: `aa` is preferred when present, else `main`.

    spillslowsum.py /path/round.jsonl [--legs] [--csv]

WHAT IT ANSWERS. The parent addendum priced the per-slab flush on NVMe and on
a NAS array with 46 GB of RAM and no cgroup, and left this open: what the
GATED arm (the one that shipped, 672b1cb72) costs and buys when the disk is
slow AND the memory is bounded at once - the only configuration where the
dirty spill pages it removes are charged against a limit that can kill. So
per (arm, disk, limit) cell it reports:

  wall     median and min-max over the reps. Compare arms WITHIN a cell only:
           this box cannot resolve a sub-15% timing effect across cells
           (memory topic nzbfast-amd-epyc-vm), and the A/A floor here is the
           `main` vs `off` pair - two binaries that differ by dead code, so
           any gap between THEM is this box's noise, not an effect. Read the
           gated arm against that floor, never against zero.
  flush    the in-process figure, which is the one to quote: the sum of the
           four `spill flush (N B): T` durations the branch logs per repair,
           and the per-slab max. On the gated arm only; 0 lines elsewhere is
           the gate working and is asserted by run.sh's own per-leg check.
  kills    oom_kill events, and bad members, per cell. 0 on every arm is NOT
           evidence the flush prevents a kill - the parent's kill needed a
           coincidence; the structural evidence is the dirty numbers below.
  dirty    the 25 ms sampled maximum of file_dirty + writeback in the scope,
           which is what the flush exists to bound, and the anon maximum
           beside it so a cell where anon alone approached the limit is
           visible rather than attributed to the spill.
  io       bytes the scope actually read and wrote through the capped device,
           from its own io.stat - so a cell whose cap did not bite is caught
           here rather than assumed. `iomax_cg` is the cap as the KERNEL read
           it back; a cell with no `rbps` in it ran UNCAPPED whatever the
           driver was asked for, and is reported as such rather than folded in.

Python 3.8 is enough. No cgroup, no root, no box: it reads files.
"""
import json
import os
import re
import sys


def median(xs):
    s = sorted(xs)
    n = len(s)
    if not n:
        return None
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def load(paths):
    legs = []
    for p in paths:
        for line in open(p):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            m = re.search(r"-(main|gated|off|aa)-(d\w+)-r(\d+)$", r.get("tag", ""))
            if not m:
                sys.stderr.write("skip, tag not this round's shape: %s\n" % r.get("tag"))
                continue
            r["_arm"], r["_disk"], r["_rep"] = m.group(1), m.group(2), int(m.group(3))
            r["_src"] = os.path.abspath(p)
            legs.append(r)
    return legs


def capped(r):
    """Did the cap the driver asked for actually reach the scope?"""
    return bool(r.get("iomax_cg")) and "rbps" in r["iomax_cg"]


def cell_rows(legs):
    cells = {}
    for r in legs:
        cells.setdefault((r["_disk"], r["limit"], r["_arm"]), []).append(r)
    rows = []
    for (disk, limit, arm), rs in sorted(cells.items()):
        walls = [r["wall"] for r in rs]
        flushes = [sum(r["flush_s"]) for r in rs if r["flush_s"]]
        per_slab = [x for r in rs for x in r["flush_s"]]
        rows.append({
            "disk": disk, "limit": limit, "arm": arm, "n": len(rs),
            "wall_med": median(walls), "wall_min": min(walls), "wall_max": max(walls),
            "flush_sum_med": median(flushes) if flushes else 0.0,
            "flush_slab_max": max(per_slab) if per_slab else 0.0,
            "flush_lines": sum(len(r["flush_s"]) for r in rs),
            "kills": sum(1 for r in rs if r.get("oom_kill")),
            "bad": sum(r.get("bad_members", 0) for r in rs),
            "dirty_max": max(r["samp_dirty_max_mib"] + r["samp_writeback_max_mib"] for r in rs),
            "anon_max": max(r["samp_anon_max_mib"] for r in rs),
            "peak_max": max(r["cg_peak_mib"] or 0 for r in rs),
            "rbytes": sum(r["io_stat"].get("rbytes", 0) for r in rs),
            "wbytes": sum(r["io_stat"].get("wbytes", 0) for r in rs),
            "uncapped": sum(1 for r in rs if not capped(r)),
        })
    return rows


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if not args:
        sys.exit(__doc__)
    legs = load(args)
    if not legs:
        sys.exit("no legs of this round's shape in %s" % ", ".join(args))
    rows = cell_rows(legs)

    print("%d legs, %d cell(s). wall s; flush s; MiB; io MB through the capped device."
          % (len(legs), len(rows)))
    bad_cap = [r for r in rows if r["uncapped"]]
    if bad_cap:
        print("WARNING: %d cell(s) had leg(s) whose io.max never reached the scope - "
              "those legs ran UNCAPPED and must not be read as a throttled disk:" % len(bad_cap))
        for r in bad_cap:
            print("  %s %s %s: %d of %d uncapped" % (r["disk"], r["limit"], r["arm"], r["uncapped"], r["n"]))
    hdr = ("disk", "limit", "arm", "n", "wall med", "wall min-max", "flush sum",
           "slab max", "lines", "kills", "bad", "dirty max", "anon max", "peak", "rMB", "wMB")
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for r in rows:
        print("| %s | %s | %s | %d | %.2f | %.2f-%.2f | %.2f | %.3f | %d | %d | %d | %.1f | %.1f | %.1f | %.0f | %.0f |"
              % (r["disk"], r["limit"], r["arm"], r["n"], r["wall_med"], r["wall_min"], r["wall_max"],
                 r["flush_sum_med"], r["flush_slab_max"], r["flush_lines"], r["kills"], r["bad"],
                 r["dirty_max"], r["anon_max"], r["peak_max"],
                 r["rbytes"] / 1e6, r["wbytes"] / 1e6))

    # The A/A floor, stated per (disk, limit) so nothing is read against zero.
    by = {}
    for r in rows:
        by.setdefault((r["disk"], r["limit"]), {})[r["arm"]] = r
    shape = "off vs aa - the SAME bytes doing the same work" if any(
        "aa" in a for a in by.values()) else "main vs off - two binaries that differ by dead code"
    print("\nA/A floor per cell (%s):" % shape)
    for (disk, limit), arms in sorted(by.items()):
        # Round 2's pair is off vs aa; round 1's is main vs off.
        pair = ("off", "aa") if "aa" in arms else ("main", "off")
        if pair[0] not in arms or pair[1] not in arms:
            print("  %s %s: no A/A pair" % (disk, limit))
            continue
        base, twin = arms[pair[0]]["wall_med"], arms[pair[1]]["wall_med"]
        floor = abs(twin - base) / base * 100.0
        line = "  %s %s: floor %.1f%% (%s %.2f, %s %.2f)" % (
            disk, limit, floor, pair[0], base, pair[1], twin)
        if "gated" in arms:
            g = arms["gated"]["wall_med"]
            eff = (g - base) / base * 100.0
            verdict = "INSIDE the floor - not resolvable here" if abs(eff) <= floor else "above the floor"
            line += "; gated %+.1f%% (%.2f) vs %s - %s" % (eff, g, pair[0], verdict)
        print(line)

    if "--legs" in flags:
        print("\nper leg:")
        for r in sorted(legs, key=lambda x: (x["_disk"], x["limit"], x["_arm"], x["_rep"])):
            print("  %-26s %-5s wall %7.2f flush %6.2f (%d) dirty %6.1f anon %6.1f kill %s cap %s"
                  % (r["tag"], r["limit"], r["wall"], sum(r["flush_s"]), len(r["flush_s"]),
                     r["samp_dirty_max_mib"] + r["samp_writeback_max_mib"], r["samp_anon_max_mib"],
                     r.get("oom_kill") or 0, "yes" if capped(r) else "NO"))


if __name__ == "__main__":
    main()
