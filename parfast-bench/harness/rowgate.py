#!/usr/bin/env python3
"""rowgate.py - parfast's single-window NTT row gate on a unix box: fold against
the forced transform with the corpus RESIDENT (no -m), an A/A copy of both arms
interleaved at every rung, and the profiled legs that give the windowed combine
ratio k.

Written 15 Sep 2026 for lane parfast-ntt-row-gate-gfni-avx512-15sep
(an internal note), which re-measured
`fastpar::ntt_min_missing` on the AVX-512 GFNI class. The Windows half of the
same round is `wcomb.ps1 -Phase rowgate`, and `rowgate.py read` reduces both.

WHY AN A/A ARM AT EVERY RUNG. The one AVX-512 GFNI box on this fleet is a KVM
guest whose A/A floor has measured 1.2% to 37% while its own quiet-box guard
passed the whole time (memory nzbfast-amd-epyc-vm). Rep-against-rep spread is
not the same thing: two reps are minutes apart, an A/A pair is seconds apart.
So every rung runs `fold force force2 fold2` (ABBA; `force2` and `fold2` are the
same arm again, never a different setting) and the reader reports a cell whose
effect does not clear its own A/A floor as UNRESOLVED rather than as a verdict.

A PEAK COLUMN, AND WHY IT IS HERE (added 17 Sep 2026). The table printed no
peak until this date, so a lane wanting one grepped `peak_mb=` over the raw log -
and a wcomb round's FIRST arm builds the fixture and emits a `CREATE rc=...
peak_mb=...` line that no later arm has, because the later arms run `-NoBuild`.
That grep caught the CREATE line and read it as the first arm's leg peak: it put
"`4m-t16` peaks at 19,082 MB against 16,429-16,490 MB on every other arm" into a
landed round record as the last surviving explanation for that arm's failures,
where the arm's own force legs peak at 16,510-16,522 MB and the five-arm ladder
is linear in thread count with no step at all. The column below is fed from `LEG `
lines only, so it cannot carry a CREATE peak, and it prints force/fold per rung.
Retraction, the three independent refutations and a box-free audit script:
rounds/t16peak-2026-09-17/. If you need the CREATE's peak, read the
CREATE line deliberately and say that is what you did.

WHY CPU AND NOT WALL. The row gate is a ratio of work. Wall divides the fold by
the pool and adds storage to both arms; the 2 Sep 2026 "~400 on the Core Ultra"
was a storage-bound wall reading. Both are recorded; the verdict is CPU.

PHASES (PHASES=ladder,create,k - in ONE process, under ONE rig lock, so no other round
lands between them):
  ladder  fold / force / force2 / fold2, no -m, RUNGS x THREADS x REPS
  create  wcomb.ps1 -Phase create's ladder, ported 17 Sep 2026: `parfast c
          -c<m>` with fold / force / force2 / fold2 at CRUNGS x CTHREADS x
          REPS, the forced arm admitted by NZBFAST_CREATE_NTT_MIN_ROWS=0 (a
          create reads NZBFAST_NTT only for 0/off, so `force` does nothing
          there), the path ASSERTED from `plan prep`'s cold build count, and
          every arm at a rung gated on one SHA-256 of the whole recovery set.
          RESIDENCY=resident asserts each forced leg made one pass over the
          corpus. Note create_ntt_min_present() is 1,024 on aarch64 and 2,048
          on x86: a fixture under that many sources silently FOLDS however you
          force it, and the path assert is what says so.
  k       wcomb.ps1's measure phase: fold at KF_RUNGS (no -m, the c_f slope) and
          forcep (force + NZBFAST_NTT_PROFILE=1) at KP_RUNGS, once resident and
          once under -m128, at KTHREADS. Definitions: wcombsum.py's header.
          Every constant is normalised to 64 KiB of width - the fold by the
          fixture's BLOCK, the combine and leaves by the SLAB - so a fixture at
          another block size reduces on the same scale and `k` can be compared
          across block sizes. KBUDGET names the -m the windowed forcep legs run
          at (default 128), because at 1 MiB a 128 MiB budget is a 128-source
          window and no window at all in the dispatcher's terms.
  validate  the DISPATCHER after a gate moves: fold / force / auto (nothing
          set) and, with ALTBIN, autoalt (auto on the binary before the change),
          interleaved per rung, at VRUNGS x VBUDGETS (`big` = no -m, or a MiB
          figure) x VTHREADS. auto should take the transform exactly where force
          beats fold; autoalt shows what the shipped gate did in the same box state.

FIXTURE, built once under $SCRATCH/$FIX if absent: MEMBERS x MEMBER_MIB MiB of
urandom, `parfast c -q -s$SLICE -c$RECOVERY`, gold.sha beside it. Damage is
pdrv's scattered picks (seed 1000+m, identical across arms at a rung). Every leg
is SHA-256 gated against the pristine members (`ok` IS "the output bytes are the
pristine bytes"), path-ASSERTED (a force leg must print `ntt syndromes (m=<m>`
and a fold leg must not), and restored by slice with a full-copy fallback.

WAITING FOR THE BOX. A lock only excludes rounds that agreed to take it, and on
15 Sep 2026 the box this was written for carried another lane's lock-free RSS
round. So before taking the lock the round waits for THREE consecutive samples,
WAIT_S apart, with no foreign `parfast` process; then pdrv's guard runs before
every leg, and foreign CPU and steal travel on every record.

RUN:  BIN=... SCRATCH=... FIX=fix64k SLICE=65536 MEMBER_MIB=64 RECOVERY=4096 \
      PHASES=ladder,k RUNGS=96,128,... THREADS=4,8 REPS=2 LABEL=64k \
      [KF_RUNGS=192,512,1024,2048,4096] [KP_RUNGS=256,1024,4096] [KTHREADS=4,8] \
      [OUT=legs.jsonl] rowgate.py
READ: rowgate.py read legs.jsonl [...]    (also reads wcomb.ps1 LEG lines)
      rowgate.py read --rungs 192,512,1024,2048 legs.jsonl
        fit the k phase's `c_f` over THOSE m rungs only. **THE RUNG SET IS A
        FREE PARAMETER OF `c_f`** - it is a least-squares SLOPE in m, so it is a
        constant only if the fold is linear in m, and on the i5 nibble part it
        is not (fold CPU per row falls from 0.120 at m = 192 to 0.072 at
        m = 4,096). Refitting one banked log over 192..2048 instead of
        192..4096 moved `c_f` 18% and `k` from 312 to 264. The rung set is
        printed beside every `c_f` and `k` with or without the flag, and a rung
        the log does not carry is REFUSED rather than dropped. Same flag, same
        meaning and same scope as wcombsum.py's, which reduces the identical
        constant from the identical legs - the two reducers must not differ on
        it. It scopes the `c_f` FIT only and deliberately not `c_w`, which is a
        per-cell ratio rather than a fit. Never compare two fitted figures
        across different rung sets without refitting both on the rungs they
        SHARE (an internal note, the 16 Sep
        estimator section).
"""
import json
import math
import os
import re
import shutil
import statistics as st
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

UNITS = {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}
SYN = re.compile(r"ntt syndromes \(m=(\d+), needed=(\d+), n=(\d+), W=(\d+), threads=(\d+)\): ([0-9.]+)(ns|µs|ms|s)")
WIN = re.compile(r"ntt window \((\d+) bytes, (\d+) slices, (\w+)\)")
PROF = re.compile(r"ntt profile \(inclusive thread-seconds\): depth0 ([0-9.]+) depth1 ([0-9.]+) depth2 ([0-9.]+) leaves ([0-9.]+)")
SLAB = re.compile(r"in (\d+) slab\(s\) of (\d+) B")
FFS = re.compile(r"feed\+fold\+solve: \+([0-9.]+)(ns|µs|ms|s)")
TILE = 4369

# THE CREATE PHASE'S THREE ADMISSION ROUTES, ported verbatim from wcomb.ps1's
# Run-Create (17 Sep 2026, lane ntt-neon-large-block-apple-2x2-17sep). The
# Windows half learned these on 16 Sep and this driver had no create ladder at
# all until today, so the reader above already knew a `create` phase while
# nothing on a unix box could produce one. `probe ok` is part of every match on
# purpose: windowed_attempt verifies one row against the fold and, on a
# disagreement or a plan that will not build, ZEROES its accumulator and lets
# the fold recompute every row - having already charged its cold plan builds,
# so `plan prep` reads cold > 0 over a leg that was entirely a fold. Requiring
# the success line refuses that leg instead. The quantity the residency assert
# compares is PASSES OVER THE CORPUS: W for copied windows, 1 for mapped, and
# the CHUNK count for the stripe-first band route - and the third is what a
# create actually does when its corpus does not fit its budget, which the first
# cut of the Windows assert did not know and would have false-refused.
CWIN = re.compile(r"create ntt rows \d+\+\d+ \(n=(\d+), (\d+) window\(s\) of (\d+),.*?probe ok\)")
CMAP = re.compile(r"create ntt rows \d+\+\d+ \(n=(\d+), mapped,.*?probe ok\)")
CBAND = re.compile(r"create stripe-first: (\d+) rows in (\d+) chunk\(s\) of (\d+) stripes \(n=(\d+),.*?probe ok\)")
COLD = re.compile(r"plan prep: \S+ over (\d+) cold build\(s\), (\d+) stripe use\(s\)")


# ---------------------------------------------------------------- reader --

def _wcomb_rows(path):
    """wcomb.ps1 LEG lines, mapped onto this driver's record fields."""
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip().lstrip("﻿")
        if not line.startswith("LEG "):
            continue
        kv = dict(t.split("=", 1) for t in line[4:].split() if "=" in t)
        good, total = kv["restored"].split("/")
        n = int(kv.get("n") or 0) or None
        out.append({
            "phase": kv["phase"], "label": kv.get("label") or kv["round"], "m": int(kv["m"]),
            "budget": kv["budget"], "arm": kv["arm"], "threads": int(kv["threads"]), "rep": int(kv["rep"]),
            "ok": kv["rc"] == "0" and good == total, "path": kv["path"], "cpu": float(kv["cpu"]),
            "wall": float(kv["wall"]), "n": n, "slice": int(kv.get("slice") or 65536),
            "foreign_cpu": kv.get("foreign_cpu"), "foreign_after": kv.get("foreign_after"),
            # Carried so the table can PRINT a peak and nobody has to grep the
            # raw log for one. Grepping `peak_mb=` is what produced the only
            # measured-claim retraction this campaign has had - see the CREATE
            # note in the module docstring. `_wcomb_rows` only ever ingests
            # `LEG ` lines, so a peak that reaches this field cannot be a
            # CREATE's by construction.
            "peak_mb": float(kv.get("peak_mb") or 0),
            "ntt_w": [int(x) for x in kv.get("ntt_w", "").split("/") if x],
            "windows": int(kv.get("windows") or 0), "slabs": int(kv.get("slabs") or 1),
        })
    return out


def load(paths):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
        if head.lstrip().startswith("{"):
            rows += [json.loads(l) for l in open(p) if l.strip()]
        else:
            rows += _wcomb_rows(p)
    bad = [r for r in rows if not r["ok"]]
    if bad:
        sys.exit("REFUSED: %d leg(s) did not restore, first %s" % (len(bad), bad[0]))
    if not rows:
        sys.exit("REFUSED: no legs in " + " ".join(paths))
    return rows


def cross(pts):
    """Log-interpolated m at which log(fold/force) first turns >= 0 reading up."""
    for (m0, y0), (m1, y1) in zip(pts, pts[1:]):
        if y0 < 0 <= y1:
            return "%.0f" % math.exp(math.log(m0) + (0 - y0) / (y1 - y0) * (math.log(m1) - math.log(m0)))
    if pts and pts[0][1] >= 0:
        return "<%d" % pts[0][0]
    if pts and pts[-1][1] < 0:
        return ">%d" % pts[-1][0]
    return "?"


def foreign(rows):
    """A group of legs' foreign CPU as (median, max, after-median), % of ONE core.

    The per-rung `foreign max` column below is not a summary and never was: a
    whole ladder sitting at a 77% median prints six unremarkable per-rung
    numbers and no total, which is how the 16 Sep 2026 windowed-ask round
    reduced two contaminated ladders into a table without saying so
    (an internal note, "The windowed ask's
    FORM"). That round was caught by a PHYSICAL IMPOSSIBILITY in the result -
    a 4,112-source ladder reading 24 rows below the resident one, and a window
    can only ever cost the transform rows - which is luck, not a mechanism.
    The median is the figure to compare between ladders: the clean one ran at
    9% and the two spent ones at 77% and 88%."""
    b = [float(r.get("foreign_cpu") or 0) for r in rows]
    a = [float(r.get("foreign_after") or 0) for r in rows]
    return st.median(b), max(b), st.median(a)


# A ladder is called out when its median foreign CPU is both this many times
# the quietest sibling's IN THE SAME FILE SET and past an absolute floor. Both
# halves are needed: the ratio alone shouts at 3% against 9% on a box that was
# quiet throughout, and the floor alone cannot tell a uniformly busy sitting
# (where every ladder is comparable) from one ladder that ran under an indexer
# pass. Against the 16 Sep round - medians 77 / 88 / 9 / 36 / 13 - this names
# the three above 25 and leaves the two that reproduce each other alone.
# It is a PRINTED WARNING and never a refusal. These are research logs, and a
# noisy ladder is still data a human may want to look at.
NOISY_RATIO = 3.0
NOISY_FLOOR = 25.0


def read_ladder(rows):
    # `create` is wcomb.ps1's create-side ladder (its own phase because the
    # legs are `parfast c` and not a repair), reduced here because the
    # reduction is the same one: fold against the forced arm, an A/A copy of
    # each, a verdict only where the effect clears its own A/A floor. Its
    # `ok` is the cross-arm output hash rather than a restore, and it carries
    # no slab column, which reads as the resident ladder's 1. It DID carry no
    # window column either until 16 Sep 2026, when the create phase learned
    # `-m` (lane create-windowed-ladder-4mib-gfni256): a create leg now
    # reports the window count its own `create ntt rows` line names, so a
    # windowed create ladder is legible here rather than reading as a
    # resident one.
    #
    # THIS GROUPS BY (label, threads) AND NOT BY BUDGET, which a windowed
    # ladder has to know: run a resident and a windowed create ladder into
    # one file set under one -Label and their rungs MERGE into a single
    # table, silently, with two different gates' cells averaged at each m.
    # Give every budget its own -Label - the same rule the affinity note in
    # wcomb.ps1's header states for masks, and for the same reason.
    #
    # AND IT GROUPS BY PHASE TOO, since 17 Sep 2026. Every wcomb.ps1 round
    # before that date ran one phase per invocation under its own -Label, so
    # the key did not need it; rowgate.py's create phase (added the same day)
    # can run `PHASES=ladder,create` in ONE process on ONE fixture, which is
    # the shape that makes a {create, repair} x {block size} 2x2 comparable -
    # same box state, same fixture, same sitting. Without the phase in the key
    # that run MERGES a repair rung and a create rung at the same m into one
    # cell. This changes no banked table: those labels are single-phase.
    lad = [r for r in rows if r["phase"] in ("ladder", "rowgate", "create")]
    keys = sorted({(r["label"], "create" if r["phase"] == "create" else "repair", r["threads"]) for r in lad})
    meds = dict((k, foreign([r for r in lad
                             if (r["label"], "create" if r["phase"] == "create" else "repair", r["threads"]) == k])[0])
                for k in keys)
    quietest = min(meds.values()) if meds else 0.0
    for (label, path, t) in keys:
        cells = {}
        for r in lad:
            if (r["label"], "create" if r["phase"] == "create" else "repair", r["threads"]) == (label, path, t):
                cells.setdefault(r["m"], []).append(r)
        print("== %s %s threads=%d  CPU-s: median of both copies of each arm (n legs); A/A = worst |X - X2| / min "
              "over the reps; verdict clears the A/A floor or is UNRESOLVED" % (label, path, t))
        print("  %5s | %8s %8s %7s | %6s %6s %6s | %-6s | %7s %7s %6s | %s"
              % ("m", "fold", "force", "F/T", "aa_F", "aa_T", "floor", "verdict", "wF", "wT", "wF/wT",
                 "foreign max | peak MB force/fold"))
        pts, wpts = [], []
        for m in sorted(cells):
            c = cells[m]

            def arm(a):
                return [r for r in c if r["arm"] == a]
            fold = arm("fold") + arm("fold2")
            force = arm("force") + arm("force2")
            if not fold or not force:
                continue
            for r in force:
                if r["path"] != "ntt":
                    sys.exit("REFUSED: force leg took the fold: %s" % r)
            for r in fold:
                if r["path"] != "fold":
                    sys.exit("REFUSED: fold leg took the transform: %s" % r)
            aa = {"fold": 0.0, "force": 0.0}
            for base in aa:
                for rep in {r["rep"] for r in c}:
                    a = [r["cpu"] for r in arm(base) if r["rep"] == rep]
                    b = [r["cpu"] for r in arm(base + "2") if r["rep"] == rep]
                    if a and b:
                        aa[base] = max(aa[base], abs(a[0] - b[0]) / min(a[0], b[0]))
            cF, cT = st.median(r["cpu"] for r in fold), st.median(r["cpu"] for r in force)
            wF, wT = st.median(r["wall"] for r in fold), st.median(r["wall"] for r in force)
            floor = max(aa.values())
            if cF / cT - 1 > floor:
                verdict = "ntt"
            elif cT / cF - 1 > floor:
                verdict = "fold"
            else:
                verdict = "unres"
            fmax = max(float(r.get("foreign_cpu") or 0) for r in c)
            # APPENDED AT THE END OF THE ROW ON PURPOSE. Two scripts parse this
            # table with a regex anchored from the line start through the floor
            # column (pinaff4m-2026-09-16/ladder-monotonicity-audit.py and
            # t16peak-2026-09-17/t16-peak-audit.py); a column added anywhere
            # else would move a group index under them.
            pkT = max((r.get("peak_mb") or 0) for r in force)
            pkF = max((r.get("peak_mb") or 0) for r in fold)
            peaks = "%.0f/%.0f" % (pkT, pkF) if (pkT or pkF) else "-"
            print("  %5d | %8.2f %8.2f %7.3f | %5.1f%% %5.1f%% %5.1f%% | %-7s | %7.2f %7.2f %6.3f | %.0f%% (%d legs) | %s"
                  % (m, cF, cT, cF / cT, 100 * aa["fold"], 100 * aa["force"], 100 * floor, verdict,
                     wF, wT, wF / wT, fmax, len(c), peaks))
            pts.append((m, math.log(cF / cT)))
            wpts.append((m, math.log(wF / wT)))
        print("  crossover (log-interpolated, median): CPU m ~ %s   wall m ~ %s" % (cross(pts), cross(wpts)))
        fmed, fmx, fafter = foreign(
            [r for r in lad
             if (r["label"], "create" if r["phase"] == "create" else "repair", r["threads"]) == (label, path, t)])
        print("  foreign CPU over %d legs: median %.0f%% of a core, max %.0f%% (after-leg median %.0f%%)"
              % (sum(len(c) for c in cells.values()), fmed, fmx, fafter))
        if len(meds) > 1 and fmed >= NOISY_FLOOR and fmed >= NOISY_RATIO * max(quietest, 1.0):
            print("  NOISY: this ladder's median foreign CPU is %.1fx the quietest ladder here (%.0f%%). "
                  "Its A/A floors and its crossover are suspect - compare it against a sibling before quoting it."
                  % (fmed / max(quietest, 1.0), quietest))


def slope(xs, ys):
    mx, my = st.fmean(xs), st.fmean(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return my - b * mx, b, max(abs(y - (my - b * mx) - b * x) for x, y in zip(xs, ys))


def read_k(rows, rungs=None):
    kr = [r for r in rows if r["phase"] == "k"]
    for (label, t) in sorted({(r["label"], r["threads"]) for r in kr}):
        tr = [r for r in kr if (r["label"], r["threads"]) == (label, t)]
        n, width0 = tr[0]["n"], tr[0]["slice"]
        # THE FOLD'S WIDTH NORMALISATION, missing until 16 Sep 2026 (lane
        # parfast-window-combine-k-1mib-16sep). c_w is divided by the slab's
        # width and c_l by it too, but c_f was divided by n alone - so on a
        # fixture whose block is not 64 KiB the ratio printed as `k` was
        # understated by exactly the width ratio, 16x on a 1 MiB one. A
        # 64 KiB round (every round before that date) is unchanged: the
        # divisor is 1.
        fold_width = width0 / 65536.0
        best = {}
        for r in tr:
            key = (r["arm"], r["budget"], r["m"])
            if key not in best or r["cpu"] < best[key]["cpu"]:
                best[key] = r
        fold = sorted((m, r["cpu"]) for (a, b, m), r in best.items() if a == "fold" and b == "big")
        print("== %s threads=%d  (k phase; every cell the minimum over reps)" % (label, t))
        if rungs is not None:
            have = {m for m, _ in fold}
            missing = [m for m in rungs if m not in have]
            if missing:
                sys.exit("REFUSED: --rungs names m=%s, which %s threads=%d does not carry (it has %s). "
                         "A fit taken over fewer rungs than asked for is the defect --rungs exists to prevent."
                         % (",".join(str(m) for m in missing), label, t,
                            ",".join(str(m) for m in sorted(have))))
            fold = [(m, c) for (m, c) in fold if m in set(rungs)]
        if len(fold) < 2:
            print("  fewer than two fold rungs, no c_f")
            continue
        a, b, res = slope([m for m, _ in fold], [c for _, c in fold])
        c_f = b / n / fold_width
        print("  fold " + " ".join("m=%d:%.2f" % x for x in fold))
        print("  c_f = %.3e CPU-s per source-row per 64 KiB (slope %.4f over n=%d, block %d B, intercept %.2f, worst residual %.2f)"
              % (c_f, b, n, width0, a, res))
        rungtxt = ",".join(str(m) for m, _ in fold)
        print("  c_f FITTED OVER RUNGS m = %s%s - a c_f quoted without this cannot be compared with another"
              % (rungtxt, " (--rungs)" if rungs is not None else " (every fold rung in the log)"))
        cws, cls = [], []
        for (arm, budget, m), r in sorted(best.items(), key=lambda kv: (kv[0][1] != "big", kv[0][2])):
            if arm != "forcep":
                continue
            if r["path"] != "ntt" or not r["profile"]:
                sys.exit("REFUSED: profiled force leg without a profile: %s" % r)
            width = r["slab_width"] / 65536.0
            per_win = st.fmean(p[0] - p[3] for p in r["profile"])
            cw = per_win / (min(m, TILE) * width)
            cws.append(cw)
            extra = ""
            if r["slabs"] == 1 and len(r["profile"]) == 1:
                cl = r["profile"][0][3] / ((n - m) * width)
                cls.append(cl)
                extra = " c_l=%.3e" % cl
            print("  forcep %-3s m=%-5d cpu=%6.2f windows=%d slabs=%d w=%d combine/win=%.3f c_w=%.3e%s"
                  % (budget, m, r["cpu"], len(r["profile"]), r["slabs"], r["slab_width"], per_win, cw, extra))
        if cws:
            med = st.median(cws)
            print("  c_w median over %d cells = %.3e (range %.3e .. %.3e)" % (len(cws), med, min(cws), max(cws)))
            print("  k = c_w / c_f = %.0f   [c_f rungs m = %s]" % (med / c_f, rungtxt))
        if cls:
            print("  c_l median = %.3e; c_l / c_f = %.0f rows" % (st.median(cls), st.median(cls) / c_f))
        if width0 != 65536:
            print("  NOTE: fixture slice %d - every constant above is per 64 KiB of width, "
                  "the fold divided by the block and the combine by the slab" % width0)


def read_validate(rows):
    """What auto (and autoalt) chose per rung, against the better of fold and force.
    `ok` = auto took whichever of the two forced arms was cheaper at that rung."""
    # A `validate` phase, or any group that carries an auto arm: wcomb.ps1's
    # rowgate phase run with -Arms fold,force,auto,autoalt is a RESIDENT
    # validation, and wcomb's own validate phase is -m128 only.
    autos = {(r["label"], r["threads"], r["budget"]) for r in rows if r["arm"] in ("auto", "autoalt")}
    vr = [r for r in rows if r["phase"] == "validate" or (r["label"], r["threads"], r["budget"]) in autos]
    for (label, t, budget) in sorted({(r["label"], r["threads"], r["budget"]) for r in vr}):
        cells = {}
        for r in vr:
            if (r["label"], r["threads"], r["budget"]) == (label, t, budget):
                cells.setdefault((r["m"], r["arm"]), []).append(r)
        print("== %s threads=%d budget=%s  validate, CPU-s median over reps" % (label, t, budget))
        print("  %5s | %7s %7s | %7s %-4s %-12s %-3s | %7s %-4s %-3s" % (
            "m", "fold", "force", "auto", "path", "W/win/slabs", "ok", "autoalt", "path", "ok"))
        for m in sorted({k[0] for k in cells}):
            def med(arm):
                c = cells.get((m, arm))
                return st.median(r["cpu"] for r in c) if c else None
            fo, fc = med("fold"), med("force")
            if fo is None or fc is None:
                continue
            want = "ntt" if fc < fo else "fold"
            out = "  %5d | %7.2f %7.2f |" % (m, fo, fc)
            for arm in ("auto", "autoalt"):
                c = cells.get((m, arm))
                if not c:
                    out += " %7s %-4s %-3s |" % ("-", "-", "-") if arm == "autoalt" else ""
                    continue
                paths = sorted({r["path"] for r in c})
                p = paths[0] if len(paths) == 1 else "/".join(paths)
                ok = "yes" if p == want else "NO"
                if arm == "auto":
                    r0 = c[0]
                    geo = "%s/%s/%s" % ("/".join(map(str, r0.get("ntt_w") or [])) or "-", r0.get("windows", 0), r0.get("slabs", 1))
                    out += " %7.2f %-4s %-12s %-3s |" % (med(arm), p, geo, ok)
                else:
                    out += " %7.2f %-4s %-3s" % (med(arm), p, ok)
            print(out)


if len(sys.argv) > 1 and sys.argv[1] == "read":
    _argv = sys.argv[2:]
    _rungs = None
    if "--rungs" in _argv:
        _i = _argv.index("--rungs")
        if _i + 1 >= len(_argv):
            sys.exit("REFUSED: --rungs needs a comma-separated list of m values")
        try:
            _rungs = [int(x) for x in _argv[_i + 1].split(",") if x.strip()]
        except ValueError:
            sys.exit("REFUSED: --rungs takes integers, e.g. --rungs 192,512,1024,2048")
        if len(_rungs) < 2:
            sys.exit("REFUSED: --rungs needs at least two rungs to fit a slope")
        del _argv[_i:_i + 2]
    rows = load(_argv)
    read_ladder(rows)
    read_k(rows, _rungs)
    read_validate(rows)
    sys.exit(0)

# ---------------------------------------------------------------- driver --

import pdrv  # noqa: E402

for _k in [k for k in os.environ if k.startswith("NZBFAST_")]:
    # A leg's environment is this process's plus the arm's overlay, so an
    # NZBFAST_* left in the launching shell would silently join every arm.
    del os.environ[_k]

BIN = os.path.abspath(os.environ["BIN"])
SCRATCH = os.path.abspath(os.environ["SCRATCH"])
FIX = os.path.join(SCRATCH, os.environ.get("FIX", "fix"))
SLICE = int(os.environ.get("SLICE", "65536"))
MEMBER_MIB = int(os.environ.get("MEMBER_MIB", "64"))
NMEMBERS = int(os.environ.get("MEMBERS", "16"))
RECOVERY = int(os.environ.get("RECOVERY", "4096"))
PHASES = os.environ.get("PHASES", "ladder").split(",")
RUNGS = [int(x) for x in os.environ.get("RUNGS", "192,256,288,320,352,384,416,448,512,640").split(",")]
THREADS = [int(x) for x in os.environ.get("THREADS", "4").split(",")]
REPS = int(os.environ.get("REPS", "2"))
KF_RUNGS = [int(x) for x in os.environ.get("KF_RUNGS", "192,512,1024,2048,4096").split(",")]
KP_RUNGS = [int(x) for x in os.environ.get("KP_RUNGS", "256,1024,4096").split(",")]
KTHREADS = [int(x) for x in os.environ.get("KTHREADS", "4").split(",")]
KBUDGET = os.environ.get("KBUDGET", "128")
ALTBIN = os.path.abspath(os.environ["ALTBIN"]) if os.environ.get("ALTBIN") else ""
VRUNGS = [int(x) for x in os.environ.get("VRUNGS", "192,256,288,320,384,512").split(",")]
VBUDGETS = os.environ.get("VBUDGETS", "big,128").split(",")
VTHREADS = [int(x) for x in os.environ.get("VTHREADS", "4").split(",")]
CRUNGS = [int(x) for x in os.environ.get("CRUNGS", os.environ.get("RUNGS", "192,256,288,320,352,384,416,448,512,640")).split(",")]
CTHREADS = [int(x) for x in os.environ.get("CTHREADS", os.environ.get("THREADS", "4")).split(",")]
CBUDGET = os.environ.get("CBUDGET", "big")
# `resident` asserts every forced create leg made ONE pass over the corpus,
# the same switch wcomb.ps1 spells -Residency. Unset asserts nothing, which
# is what a leg that crossed silently into the windowed gate publishes under.
RESIDENCY = os.environ.get("RESIDENCY", "")
LABEL = os.environ.get("LABEL", "%dk" % (SLICE // 1024))
OUT = os.path.abspath(os.environ.get("OUT", os.path.join(SCRATCH, "rowgate.jsonl")))
WAIT_S = int(os.environ.get("WAIT_S", "20"))
LEGS = os.path.join(SCRATCH, "legs")
PRISTINE, WORK = os.path.join(FIX, "pristine"), os.path.join(FIX, "work")
MEMBERS = ["m%02d.bin" % i for i in range(1, NMEMBERS + 1)]


def secs(v, u):
    return float(v) * UNITS[u]


def build_fixture():
    goldp = os.path.join(FIX, "gold.sha")
    if not os.path.exists(goldp):
        if os.path.exists(FIX):
            shutil.rmtree(FIX)
        os.makedirs(PRISTINE)
        for nm in MEMBERS:
            with open(os.path.join(PRISTINE, nm), "wb") as f:
                for _ in range(MEMBER_MIB):
                    f.write(os.urandom(1 << 20))
        t0 = time.monotonic()
        p = subprocess.run([BIN, "c", "-q", "-q", "-s%d" % SLICE, "-c%d" % RECOVERY, "set.par2"] + MEMBERS,
                           cwd=PRISTINE, capture_output=True)
        if p.returncode != 0:
            sys.exit("CREATE-FAIL rc=%d %s" % (p.returncode, p.stderr[-400:]))
        with open(goldp, "w") as f:
            for nm in MEMBERS:
                f.write("%s  %s\n" % (pdrv.sha256_file(os.path.join(PRISTINE, nm)), nm))
        shutil.copytree(PRISTINE, WORK)
        print("CREATE fix=%s members=%d x %d MiB slice=%d recovery=%d secs=%.1f"
              % (FIX, NMEMBERS, MEMBER_MIB, SLICE, RECOVERY, time.monotonic() - t0), flush=True)
    gold = dict((l.split()[1], l.split()[0]) for l in open(goldp))
    keep = set(os.listdir(PRISTINE))
    good, bad = pdrv.gate(WORK, MEMBERS, gold)
    if bad:
        sys.exit("FIXTURE-FAIL work copy not pristine: %s" % bad)
    n = sum(-(-os.path.getsize(os.path.join(PRISTINE, nm)) // SLICE) for nm in MEMBERS)
    print("FIXTURE fix=%s n=%d slice=%d recovery=%d files=%d" % (FIX, n, SLICE, RECOVERY, len(keep)), flush=True)
    return gold, keep, n


def wait_for_box():
    """Three clean samples in a row with no foreign parfast, however long that takes.

    Matched on the basename's PREFIX: the lane this was written beside ran
    `parfast-base` and `parfast-main`, which an exact `comm == parfast` misses."""
    clean, waited = 0, 0
    while clean < 3:
        out = subprocess.run(["ps", "-Ao", "pid=,args="], capture_output=True, text=True).stdout
        busy = []
        for l in out.splitlines():
            f = l.split()
            if len(f) >= 2 and int(f[0]) != os.getpid() and os.path.basename(f[1]).startswith(("parfast", "par2")):
                busy.append(l.strip()[:80])
        clean = 0 if busy else clean + 1
        if busy and waited % 600 < WAIT_S:
            print("WAIT-FOREIGN-PARFAST %s (%dm) ts=%s" % (busy[:3], waited // 60, pdrv.utcnow()), flush=True)
        time.sleep(WAIT_S)
        waited += WAIT_S


def leg(phase, gold, keep, n, m, budget, arm, threads, rep, picks):
    base = "fold" if arm.startswith("fold") else "force" if arm.startswith("force") else "auto"
    env = {"NZBFAST_REPAIR_TIMING": "1", "NZBFAST_NO_ENRICH": "1"}
    if base != "auto":
        env["NZBFAST_NTT"] = "0" if base == "fold" else "force"
    if arm == "forcep":
        env["NZBFAST_NTT_PROFILE"] = "1"
    # `autoalt` is `auto` on ALTBIN, the binary before the change, so a moved
    # gate is compared rung by rung in the same box state.
    exe = ALTBIN if arm == "autoalt" else BIN
    argv = ["r", "-t%d" % threads, "-q"] + ([] if budget == "big" else ["-m" + budget]) + ["set.par2"]
    tag = "%s-%s-m%d-%s-%s-t%d-r%d" % (LABEL, phase, m, budget, arm, threads, rep)
    wrote = pdrv.apply_damage(WORK, MEMBERS, SLICE, picks, 1000 + m)
    l0 = os.getloadavg()[0]
    res = pdrv.run_leg(exe, argv, WORK, os.path.join(LEGS, tag), env)
    l1 = os.getloadavg()[0]
    err = open(os.path.join(LEGS, tag + ".err"), errors="replace").read()
    good, bad = pdrv.gate(WORK, MEMBERS, gold)
    ok = res["rc"] == 0 and not bad
    syn = SYN.findall(err)
    path = "ntt" if syn else "fold"
    strays = pdrv.remove_strays(WORK, keep)
    pdrv.restore_slices(WORK, PRISTINE, MEMBERS, SLICE, picks)
    _, still = pdrv.gate(WORK, MEMBERS, gold)
    if still:
        for nm in still:
            shutil.copyfile(os.path.join(PRISTINE, nm), os.path.join(WORK, nm))
        _, still = pdrv.gate(WORK, MEMBERS, gold)
        print("RESTORE-FALLBACK %s now_bad=%s" % (tag, still), flush=True)
        if still:
            sys.exit("RESTORE-FAIL %s" % tag)
    if not ok:
        sys.exit("GATE-FAIL %s rc=%d bad=%s (stderr %s.err)" % (tag, res["rc"], bad, tag))
    if base == "force" and (not syn or int(syn[0][0]) != m):
        sys.exit("PATH-FAIL %s: a force leg did not run the transform over m=%d (%s)" % (tag, m, syn[:1]))
    if base == "fold" and syn:
        sys.exit("PATH-FAIL %s: a fold leg printed an ntt syndromes line" % tag)
    slab = SLAB.search(err)
    ffs = FFS.search(err)
    rec = {
        "phase": phase, "label": LABEL, "bin": exe, "slice": SLICE, "n": n, "m": m, "budget": budget, "arm": arm,
        "threads": threads, "rep": rep, "ok": ok, "path": path, "wall": res["wall"], "cpu": res["cpu"],
        "peak_mb": res["peak_mb"], "foreign_cpu": res["foreign_cpu"], "foreign_after": res["foreign_after"],
        "steal_pct": res["steal_pct"], "load_before": round(l0, 2), "load_after": round(l1, 2),
        "ntt_w": sorted({int(s[3]) for s in syn}), "ntt_threads": sorted({int(s[4]) for s in syn}),
        "syn_s": round(sum(secs(s[5], s[6]) for s in syn), 4) if syn else None,
        "windows": len(WIN.findall(err)), "slabs": int(slab.group(1)) if slab else 1,
        "slab_width": int(slab.group(2)) if slab else SLICE,
        "profile": [[float(x) for x in p] for p in PROF.findall(err)],
        "ffs_s": round(secs(ffs.group(1), ffs.group(2)), 4) if ffs else None,
        "blocks_written": wrote, "strays": strays, "ts": pdrv.utcnow(),
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-38s ok path=%-4s wall=%7.2f cpu=%8.2f W=%s win=%d slabs=%d foreign=%s/%s steal=%s load=%.1f/%.1f%s"
          % (tag, path, res["wall"], res["cpu"], rec["ntt_w"], rec["windows"], rec["slabs"], res["foreign_cpu"],
             res["foreign_after"], res["steal_pct"], l0, l1, pdrv.rig_token()), flush=True)


def create_leg(gold, n, m, budget, arm, threads, rep, cref):
    """One `parfast c` leg - wcomb.ps1's Run-Create, arm for arm.

    The forced arms are NOT the repair's. A create reads `NZBFAST_NTT` only for
    0/off, so `force` does nothing there; the create's transform is admitted by
    `NZBFAST_CREATE_NTT_MIN_ROWS=0`, which is `create_ntt_min_rows`'s own bench
    knob. `fold2` / `force2` are the A/A copies - the same arm again, never a
    different setting.
    """
    base = "fold" if arm.startswith("fold") else "force"
    env = {"NZBFAST_REPAIR_TIMING": "1", "NZBFAST_NO_ENRICH": "1"}
    if base == "fold":
        env["NZBFAST_NTT"] = "0"
    else:
        env["NZBFAST_CREATE_NTT_MIN_ROWS"] = "0"
    for f in os.listdir(WORK):
        if f.startswith("cr") and f.endswith(".par2"):
            os.remove(os.path.join(WORK, f))
    argv = ["c", "-q", "-t%d" % threads, "-s%d" % SLICE, "-c%d" % m]
    if budget != "big":
        argv.append("-m" + budget)
    argv += ["cr.par2"] + MEMBERS
    tag = "%s-create-m%d-%s-%s-t%d-r%d" % (LABEL, m, budget, arm, threads, rep)
    l0 = os.getloadavg()[0]
    res = pdrv.run_leg(BIN, argv, WORK, os.path.join(LEGS, tag), env)
    l1 = os.getloadavg()[0]
    err = open(os.path.join(LEGS, tag + ".err"), errors="replace").read()
    # The MEMBERS are inputs to a create and must come out untouched; the
    # ladder phase damages the same work copy, so gate them here too rather
    # than trusting the phase order.
    _, badm = pdrv.gate(WORK, MEMBERS, gold)
    if badm:
        sys.exit("GATE-FAIL %s: create altered its own inputs %s" % (tag, badm))
    cold = sum(int(mm.group(1)) for mm in COLD.finditer(err))
    path = "ntt" if cold > 0 else "fold"
    if (base == "fold") != (path == "fold"):
        sys.exit("PATH-FAIL %s: arm=%s took path=%s (cold builds %d)" % (tag, arm, path, cold))
    win, mapd, band = CWIN.findall(err), CMAP.findall(err), CBAND.findall(err)
    cslices = [int(g[2]) for g in win]
    passes = [int(g[1]) for g in win] + [1] * len(mapd) + [int(g[1]) for g in band]
    route = "band" if band else "mapped" if mapd else "copied" if win else "none"
    if RESIDENCY and base == "force":
        if not passes:
            sys.exit("RESIDENCY-FAIL %s want=%s: no create transform success line - none of the three routes "
                     "(copied windows, mapped, stripe-first bands) reported 'probe ok', so the create either never "
                     "reached one or threw its transform away, and cold_builds=%d cannot tell that from a transform "
                     "that ran" % (tag, RESIDENCY, cold))
        if RESIDENCY == "resident":
            if max(passes) > 1:
                sys.exit("RESIDENCY-FAIL %s want=resident route=%s passes=%s - more than one pass over the corpus, "
                         "so this rung is not measuring the resident gate" % (tag, route, passes))
            bad = [w for w in cslices if w != n]
            if bad:
                sys.exit("RESIDENCY-FAIL %s want=resident win_slices=%s expected=%d - one window, but it did not "
                         "cover every source" % (tag, bad, n))
        elif RESIDENCY == "windowed":
            if min(passes) < 2:
                sys.exit("RESIDENCY-FAIL %s want=windowed route=%s passes=%s - at least one transform call made a "
                         "SINGLE pass, so this rung ran resident under a -m" % (tag, route, passes))
        else:
            sys.exit("RESIDENCY-FAIL unknown RESIDENCY=%s (want resident or windowed)" % RESIDENCY)
    # The cross-arm gate. The recovery files are the create's WHOLE output, so
    # one hash over them in name order is "these bytes are those bytes" - the
    # create path's equivalent of the repair ladder's restore check, and the
    # only thing that says the forced transform computed the same recovery set
    # the fold did.
    outs = sorted(f for f in os.listdir(WORK) if f.startswith("cr") and f.endswith(".par2"))
    dig = ",".join("%s:%s" % (f, pdrv.sha256_file(os.path.join(WORK, f))) for f in outs)
    obytes = sum(os.path.getsize(os.path.join(WORK, f)) for f in outs)
    cref.setdefault(m, dig)
    match = cref[m] == dig
    for f in outs:
        os.remove(os.path.join(WORK, f))
    ok = res["rc"] == 0 and match and bool(outs)
    rec = {
        "phase": "create", "label": LABEL, "bin": BIN, "slice": SLICE, "n": n, "m": m, "budget": budget, "arm": arm,
        "threads": threads, "rep": rep, "ok": ok, "path": path, "wall": res["wall"], "cpu": res["cpu"],
        "peak_mb": res["peak_mb"], "foreign_cpu": res["foreign_cpu"], "foreign_after": res["foreign_after"],
        "steal_pct": res["steal_pct"], "load_before": round(l0, 2), "load_after": round(l1, 2),
        "match": int(match), "out_files": len(outs), "out_bytes": obytes, "route": route,
        "windows": max(passes) if passes else 0, "win_slices": cslices[:3], "cold_builds": cold,
        "ntt_w": [], "slabs": 1, "slab_width": SLICE, "ts": pdrv.utcnow(),
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-38s %s path=%-4s route=%-6s wall=%7.2f cpu=%8.2f win=%d files=%d foreign=%s/%s load=%.1f/%.1f%s"
          % (tag, "ok" if ok else "BAD", path, route, res["wall"], res["cpu"], rec["windows"], len(outs),
             res["foreign_cpu"], res["foreign_after"], l0, l1, pdrv.rig_token()), flush=True)
    if res["rc"] != 0:
        sys.exit("CREATE-FAIL %s rc=%d (stderr %s.err)" % (tag, res["rc"], tag))
    if not outs:
        sys.exit("CREATE-FAIL %s wrote no recovery files" % tag)
    if not match:
        sys.exit("CREATE-FAIL %s output differs from the first arm at m=%d" % (tag, m))


def main():
    os.makedirs(LEGS, exist_ok=True)
    print("ROUND label=%s phases=%s start=%s" % (LABEL, ",".join(PHASES), pdrv.utcnow()), flush=True)
    lock = pdrv.RigLock(os.path.join(SCRATCH, "rowgate.lock"))
    while True:
        # A round that holds the lock can sit between legs for a minute with no
        # parfast running, so a clean box is not a free lock: on LOCK-BUSY (17)
        # go back to waiting rather than lose the round to another lane's gap.
        wait_for_box()
        try:
            lock.take()
            break
        except SystemExit as e:
            if e.code != 17:
                raise
            print("WAIT-LOCK ts=%s" % pdrv.utcnow(), flush=True)
            time.sleep(60)
    try:
        pdrv.box_facts()
        pdrv.bin_facts([BIN] + ([ALTBIN] if ALTBIN else []))
        pdrv.harness_facts()
        gold, keep, n = build_fixture()
        print("PLAN label=%s phases=%s rungs=%s threads=%s reps=%d kf=%s kp=%s kthreads=%s vrungs=%s vbudgets=%s "
              "vthreads=%s crungs=%s cthreads=%s cbudget=%s residency=%s altbin=%s out=%s"
              % (LABEL, PHASES, RUNGS, THREADS, REPS, KF_RUNGS, KP_RUNGS, KTHREADS,
                 VRUNGS, VBUDGETS, VTHREADS, CRUNGS, CTHREADS, CBUDGET, RESIDENCY or "-",
                 ALTBIN or "-", OUT), flush=True)
        cref = {}
        for rep in range(1, REPS + 1):
            if "ladder" in PHASES:
                order = ["fold", "force", "force2", "fold2"] if rep % 2 else ["force", "fold", "fold2", "force2"]
                for m in RUNGS:
                    picks = pdrv.damage_picks(WORK, MEMBERS, SLICE, m, 1000 + m)
                    for t in THREADS:
                        for arm in order:
                            leg("ladder", gold, keep, n, m, "big", arm, t, rep, picks)
            if "create" in PHASES:
                # ABBA, flipped on alternate reps, so neither copy of an arm
                # always runs first - the shape the 17 Sep Snapdragon round
                # names as the one a 1% position bias can otherwise move a
                # crossover rung with.
                order = ["fold", "force", "force2", "fold2"] if rep % 2 else ["force", "fold", "fold2", "force2"]
                for m in CRUNGS:
                    for t in CTHREADS:
                        for arm in order:
                            create_leg(gold, n, m, CBUDGET, arm, t, rep, cref)
            if "k" in PHASES:
                for t in KTHREADS:
                    for m in KF_RUNGS:
                        leg("k", gold, keep, n, m, "big", "fold", t, rep,
                            pdrv.damage_picks(WORK, MEMBERS, SLICE, m, 1000 + m))
                    for m in KP_RUNGS:
                        picks = pdrv.damage_picks(WORK, MEMBERS, SLICE, m, 1000 + m)
                        leg("k", gold, keep, n, m, "big", "forcep", t, rep, picks)
                        leg("k", gold, keep, n, m, KBUDGET, "forcep", t, rep, picks)
            if "validate" in PHASES:
                varms = ["fold", "force", "auto"] + (["autoalt"] if ALTBIN else [])
                if rep % 2 == 0:
                    varms.reverse()
                for budget in VBUDGETS:
                    for m in VRUNGS:
                        picks = pdrv.damage_picks(WORK, MEMBERS, SLICE, m, 1000 + m)
                        for t in VTHREADS:
                            for arm in varms:
                                leg("validate", gold, keep, n, m, budget, arm, t, rep, picks)
        print("ALL DONE ts=%s" % pdrv.utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
