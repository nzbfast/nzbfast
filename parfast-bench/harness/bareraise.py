#!/usr/bin/env python3
"""bareraise.py - does a person's large `-m` buy WALL TIME on a BARE box?

Written 16 Sep 2026 for an internal note, the
timing half the published-limit raise shipped without
(an internal note addendum 2 proved the SHAPE
of the raise on a bare box and took no timing claim).

THE ARMS ARE THE SAME BINARY. Since 15 Sep 2026 a limit a PERSON set raises the
repair's solve window and NTT retention budget above the host default of RAM/4,
capped at cgroup/4 where a cgroup limit exists. On a BARE box (no cgroup limit)
the raise stands as asked, so the honest A/B of the feature as shipped is one
binary run two ways over one fixture:

    host   `parfast r`          - the host default, RAM/4
    raise  `parfast r -m<BIG>`  - the person's figure

Both arms must solve the SAME damage, and so must every REP: the damage plan
comes from ONE seed for the whole round, not one per rep. That is not tidiness.
The slab plan is `reconstruct::plan_solve_for(needed, bs,
selection_structured(n_inputs, &missing, &exps))` - it is computed from the
damage PATTERN and the exponents it selects, not from the block count alone -
so two reps with the same `m` and a different seed can DISPATCH differently.
Measured here on 16 Sep 2026: at m = 3,100 of 3,200 blocks, seed 1001 put the
host arm in 2 slabs and seed 1002 put it in 1, which makes that rep's two arms
the same dispatch and no A/B at all. One seed, one cell, every rep.

A/A IS NOT OPTIONAL HERE. The effect being looked for is a wall-time difference
between two dispatches of the same code, and this fleet has boxes with a 13-37%
A/A floor on a bad day. Each arm therefore runs as a PAIR against a byte copy of
the binary at a second path (`host`/`host_aa`, `raise`/`raise_aa`): the pair's
spread IS the floor, measured in the same round, in the same order, on the same
box - and a difference inside it is a nil result, which is a result.

RUN:
    BIN=/path/parfast BIN_AA=/path/parfast_aa SCRATCH=/dir M=6200 \
    [SLICE=1048576] [RAISE=14000] [REPS=3] [THREADS=8] [SEED=1001] [TAG=x] \
    [OUT=legs.jsonl] bareraise.py

FIXTURE, built once under $SCRATCH/fix (the recipe memladder.py's header
carries, resized so the solve window crosses the host quarter):

    mkdir -p fix/pristine && cd fix/pristine
    for i in $(seq -w 1 16); do dd if=/dev/urandom of=m$i.bin bs=1048576 count=400; done
    sha256sum m*.bin > ../gold.sha
    parfast c -q -t8 -s1048576 -c6300 set.par2 m*.bin
    mkdir ../work && cp * ../work/

SIZING, and it is the whole point: the solve window is 2 * m * SLICE, and the
round says nothing unless that window sits ABOVE the host default (RAM/4) and
BELOW what `-m RAISE` asks for. Check it before the fixture, not after:
mem-floor prints the dispatch and `slabs` is the tell - the host arm slabs, the
raised arm does not.

AND ON THE NTT/TRANSFORM PATH THERE IS A SECOND TERM TO SIZE, because `-m`
raises the NTT RETENTION BUDGET as well as the solve window. The transform
takes the PRESENT corpus a budget-sized window at a time and rebuilds its
upper tree once per window, so the raise moves the WINDOW COUNT too - a term
the fold has no analogue of. A round on that path must therefore size BOTH:
`2 * m * SLICE` across the host quarter for the slabs, and
`n_present * SLICE` across it for the windows. The two pull against each
other (every block that is missing is a block that is not present), so the
fixture has to be roughly 1.5x the window in source bytes, and a shape with
97% of its blocks damaged - which is what crossing the quarter needs in a
SMALL fixture - leaves too few present blocks for the transform to be chosen
at all. VERIFY THE DISPATCH ON ONE LEG PER ARM BEFORE COMMITTING A ROUND:
`path` must read `ntt` on both arms and `wins` must differ between them,
or the round is measuring the slab count and must say so.

Every leg is SHA-256 gated against the pristine members (so `ok` IS "the output
bytes are the pristine bytes") and restored by slice; a leg that is not
byte-exact is damage and not data, and the driver stops. pdrv.run_leg gates each
leg on a quiet box and records foreign CPU either side plus /proc/stat steal
across the leg. Paging is read separately from /proc/vmstat (pswpin/pswpout
across the leg): a raised window that is most of RAM and pages is not a win, and
a swap-in a leg's wall carries must be visible, not inferred.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pdrv  # noqa: E402

S = os.environ["SCRATCH"]
BIN = os.environ["BIN"]
BIN_AA = os.environ["BIN_AA"]
FIX = os.environ.get("FIX", "fix")
PRISTINE = os.path.join(S, FIX, "pristine")
WORK = os.path.join(S, FIX, "work")
SLICE = int(os.environ.get("SLICE", "1048576"))
M = int(os.environ.get("M", "6200"))
RAISE = os.environ.get("RAISE", "14000")
REPS = int(os.environ.get("REPS", "3"))
SEED = int(os.environ.get("SEED", "1001"))
THREADS = os.environ.get("THREADS", "8")
TAG = os.environ.get("TAG", "")
OUT = os.path.join(S, os.environ.get("OUT", "legs.jsonl"))
LOGDIR = os.path.join(S, "legs")
os.makedirs(LOGDIR, exist_ok=True)

# label -> (binary, budget or None)
ARMS = [
    ("host", BIN, None),
    ("host_aa", BIN_AA, None),
    ("raise", BIN, RAISE),
    ("raise_aa", BIN_AA, RAISE),
]

members = sorted(f for f in os.listdir(PRISTINE) if f.endswith(".bin"))
gold = {}
for line in open(os.path.join(S, FIX, "gold.sha")):
    h, name = line.split()
    gold[name.lstrip("*")] = h


def vmstat_pages():
    """(pswpin, pswpout) in pages, or None off Linux."""
    try:
        out = {}
        for line in open("/proc/vmstat"):
            k, _, v = line.partition(" ")
            if k in ("pswpin", "pswpout"):
                out[k] = int(v)
        return (out["pswpin"], out["pswpout"])
    except Exception:
        return None


def dispatch(errpath):
    """The decision the leg took, from the NZBFAST_REPAIR_TIMING stderr.

    Read rather than assumed: the arms are one binary and the ONLY thing that
    may differ between them is what the budget bought, so a round whose two
    arms dispatched identically has measured nothing and must say so.
    """
    import re
    err = open(errpath, errors="replace").read()
    slabs = re.search(r"in (\d+) slab\(s\) of (\d+) B", err)
    syn = re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=(\d+), W=(\d+), threads=(\d+)\)", err)
    win = re.findall(r"ntt window \((\d+) bytes, (\d+) slices, (\w+)\)", err)
    ff = re.search(r"feed\+fold\+solve: \+([0-9.]+)(µs|ms|s)", err)
    fv = re.search(r"final verify: \+([0-9.]+)(µs|ms|s)", err)
    mult = {"µs": 1e-6, "ms": 1e-3, "s": 1.0}

    def sec(mm):
        return round(float(mm.group(1)) * mult[mm.group(2)], 3) if mm else None

    return {
        "path": "ntt" if syn else "fold",
        "slabs": int(slabs.group(1)) if slabs else 1,
        "slab_width": int(slabs.group(2)) if slabs else SLICE,
        "ntt_w": sorted({int(w) for (_, w, _) in syn}),
        "ntt_threads": sorted({int(t) for (_, _, t) in syn}),
        # `ntt window` prints only for a window the RETENTION BUDGET
        # filled mid-stream; the tail the feeders leave behind is
        # transformed in `finish` and prints no such line. So the
        # WINDOW COUNT - the term the transform pays its upper tree
        # for once each, and the one the raise moves - is the number of
        # `ntt syndromes` lines, which every window prints, and
        # `ntt_windows` alone undercounts it by exactly one. Both are
        # recorded: a round whose two arms took the same number of
        # windows has measured the solve slab and nothing else, and has
        # to say so.
        "ntt_windows": len(win),
        "ntt_syn_calls": len(syn),
        "ntt_window_states": [st for (_, _, st) in win],
        "feed_fold_solve": sec(ff),
        "final_verify": sec(fv),
    }


def run_leg(rep, label, exe, budget, picks, order):
    argv = ["r", "-t" + THREADS, "-q"]
    if budget is not None:
        argv.append("-m" + budget)
    argv.append("set.par2")
    tag = "m%d-%s-r%d%s" % (M, label, rep, ("-" + TAG) if TAG else "")
    logbase = os.path.join(LOGDIR, tag)
    pdrv.apply_damage(WORK, members, SLICE, picks, 1)
    sw0 = vmstat_pages()
    res = pdrv.run_leg(exe, argv, WORK, logbase, env_extra={"NZBFAST_REPAIR_TIMING": "1"})
    sw1 = vmstat_pages()
    # `pdrv.gate` returns (good, bad), NOT a bool: `and pdrv.gate(...)` is
    # true for every possible return it has, so a leg that produced garbage
    # would report ok and the round would publish it. Unpack it.
    _good, bad = pdrv.gate(WORK, members, gold)
    ok = res["rc"] == 0 and not bad
    pdrv.restore_slices(WORK, PRISTINE, members, SLICE, picks)
    _good, bad_after = pdrv.gate(WORK, members, gold)
    if bad_after:
        raise SystemExit("restore failed at %s: %s" % (tag, bad_after))
    rec = dict(res)
    rec.update(dispatch(logbase + ".err"))
    rec.update({
        "tag": TAG, "m": M, "slice": SLICE, "rep": rep, "arm": label, "bin": exe,
        "budget": budget or "host", "threads": int(THREADS), "ok": ok, "bad": bad, "order": order,
        "swap_in_pages": (sw1[0] - sw0[0]) if (sw0 and sw1) else None,
        "swap_out_pages": (sw1[1] - sw0[1]) if (sw0 and sw1) else None,
        "utc": pdrv.utcnow(),
    })
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-24s rc=%d ok=%s wall=%8.2f cpu=%9.2f peak=%7.1fMB slabs=%d path=%-4s wins=%d W=%s "
          "ffs=%s swap=%s/%s fgn=%.1f/%.1f steal=%s"
          % (tag, rec["rc"], ok, rec["wall"], rec["cpu"], rec["peak_mb"], rec["slabs"], rec["path"],
             rec["ntt_syn_calls"], rec["ntt_w"], rec["feed_fold_solve"], rec["swap_in_pages"],
             rec["swap_out_pages"], rec["foreign_cpu"], rec["foreign_after"], rec["steal_pct"]),
          flush=True)
    if not ok:
        raise SystemExit("NOT byte-exact at " + tag + " - that is damage, not data")
    return rec


if __name__ == "__main__":
    _good, bad = pdrv.gate(WORK, members, gold)
    if bad:
        raise SystemExit("work copy is not pristine at start: %s" % bad)
    # The HARNESS's own provenance, and the round-start twin of the
    # per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
    # banked log cannot be traced to the harness revision that wrote
    # it (census an internal note).
    pdrv.harness_facts()
    # NOT `json.dumps(pdrv.bin_facts(...))`, which is what these two lines
    # were until 21 Sep 2026: both functions PRINT and return None, so the
    # round banked the real BIN and BOX lines AND a literal `BIN   null`
    # and `BOX   null` beside them - and `s2sum.py` matches `BOX ` with a
    # trailing space, so which of the two a fold reports is the file order
    # (an internal note section 5). This driver
    # banks its round log on STDOUT, so the printing halves are the right
    # ones here; a driver that tees wants `bin_lines` / `box_line`.
    pdrv.bin_facts([BIN, BIN_AA])
    pdrv.box_facts()
    print("SHAPE m=%d slice=%d window=%d MiB raise=-m%s reps=%d threads=%s"
          % (M, SLICE, 2 * M * SLICE // (1 << 20), RAISE, REPS, THREADS), flush=True)
    print("SEED  %d (one plan for every rep)" % SEED, flush=True)
    t0 = time.monotonic()
    # ONE plan for the whole round - see the header. A per-rep seed makes each
    # rep a different cell, and silently: the legs all run, all gate, and the
    # reps simply are not comparable.
    picks = pdrv.damage_picks(WORK, members, SLICE, M, SEED)
    for rep in range(1, REPS + 1):
        # Rotated by rep and reversed on even reps: no arm keeps the same
        # neighbours, and none keeps the cold-cache first slot of a rep.
        order = ARMS[(rep - 1) % len(ARMS):] + ARMS[:(rep - 1) % len(ARMS)]
        if rep % 2 == 0:
            order = list(reversed(order))
        for i, (label, exe, budget) in enumerate(order):
            run_leg(rep, label, exe, budget, picks, i)
    print("ALL DONE in %.0f s" % (time.monotonic() - t0), flush=True)
