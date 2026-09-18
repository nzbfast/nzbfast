#!/usr/bin/env python3
"""muslmem.py <cg-dir>... - claim parfast-musl-allocator-speed-15sep (an internal note, the musl-allocator addendum). - per cell x arm: legs, kills, byte-exact, anon peak range,
tightest instant (max over the 25 ms trace of anon + file_dirty + file_writeback +
kernel), beside the musl addendum's rows (anon, tightest; MiB, four reps)."""
import json, os, sys
from collections import defaultdict

ADDENDUM_MUSL = {  # (set, m, budget, inplace) -> (anon lo, hi, tightest lo, hi)
    ("fix", 4096, "128", False): (344, 347, 371, 378),
    ("fix", 4096, "192", False): (363, 370, 387, 390),
    ("fix", 4096, "256", False): (377, 404, 398, 412),
    ("fix", 1024, "256", False): (275, 276, 326, 338),
    ("fix", 2048, "256", False): (303, 306, 341, 353),
    ("fix1m", 192, "256", False): (153, 155, 217, 229),
    ("fix", 4096, "256", True): (373, 374, 396, 422),
    ("fix", 192, "none", False): (97, 99, 174, 184),
    ("fix", 1024, "none", False): (236, 236, 290, 301),
}
MIB = 1048576.0
cells = defaultdict(lambda: defaultdict(list))
for d in sys.argv[1:]:
    arm = os.path.basename(os.path.normpath(d)).replace("cg-", "")
    for line in open(os.path.join(d, "cg512.jsonl")):
        r = json.loads(line)
        inplace = any("inplace" in x for x in r["xenv"])
        key = (r["set"], r["m"], r["budget"], inplace)
        tight = 0.0
        sp = os.path.join(d, "legs", r["tag"] + ".samp")
        try:
            with open(sp) as f:
                next(f)
                for ln in f:
                    t, cur, anon, fil, dirty, wb, kern, pgscan = ln.split()
                    tight = max(tight, (int(anon) + int(dirty) + int(wb) + int(kern)) / MIB)
        except (OSError, StopIteration):
            tight = float("nan")
        cells[key][arm].append((r["samp_anon_max_mib"], tight, r["ok"], r["oom_kill"] or 0, r["path"], r["ntt_w"], r["slabs"], r["ntt_windows"], r["cpu"], r["wall"]))
tot = kills = notok = 0
print("%-26s %-5s %4s %5s %-15s %-15s %-12s | addendum musl anon / tightest" % ("cell", "arm", "legs", "kills", "anon", "tightest", "dispatch"))
for key in ADDENDUM_MUSL:
    for arm, rows in sorted(cells[key].items()):
        tot += len(rows)
        k = sum(x[3] for x in rows)
        kills += k
        notok += sum(1 for x in rows if not x[2])
        an = [x[0] for x in rows]
        ti = [x[1] for x in rows]
        disp = sorted({"%s/%s/%d/%d" % (x[4], ",".join(map(str, x[5])) or "-", x[6], x[7]) for x in rows})
        a = ADDENDUM_MUSL[key]
        print("%-26s %-5s %4d %5d %6.0f-%-8.0f %6.0f-%-8.0f %-12s | %d-%d / %d-%d   cpu %s"
              % ("%s m=%d -m%s%s" % (key[0], key[1], key[2], " inplace" if key[3] else ""), arm, len(rows), k,
                 min(an), max(an), min(ti), max(ti), " ".join(disp), a[0], a[1], a[2], a[3],
                 "/".join("%.0f" % x[8] for x in rows)))
print("legs=%d kills=%d not-byte-exact=%d; headroom at the tightest instant = 512 - tightest" % (tot, kills, notok))
