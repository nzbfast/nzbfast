#!/usr/bin/env python3
"""nttladder.py - is the NTT's per-WINDOW upper-tree charge linear in the
WINDOW COUNT, and is `c_w` stable across `m`?

Written 16 Sep 2026 for section 8.11 of
an internal note, which closes that note's
section 8.8 limit in as many words: "Two cells, not a curve. Cell A has one
extra window; nothing here says what three or ten windows cost, though the
model says linearly."

THE SHAPE OF THE EXPERIMENT. `harness/bareraise.py` is a two-arm A/B:
one binary run as `host` and `raise` with an A/A pair each. This is a LADDER
over one corpus - the same damage, the same solve plan, the same binary - with
only the RETENTION WINDOW COUNT moving, so each rung is an arm and the pair at
that rung is its floor.

WHY `NZBFAST_NTT_BUDGET` AND NOT `-m`. `-m` moves TWO counts (section 8.7): a
solve SLAB splits the block's WIDTH and a retention WINDOW splits the SOURCES
at full width, and a ladder that moves both measures neither. `fastpar::
ntt_budget_within_published` honours `NZBFAST_NTT_BUDGET` ABSOLUTELY, in either
direction, BEFORE `clamp_to_published` - so it moves the retention budget
without touching `reconstruct::solve_window_budget`, and every rung is the same
solve by construction. That makes this an INSTRUMENT round: the knob is not the
one a person turns. Two `-m` rungs are therefore carried as CONTROLS, at the
two window counts `-m` can reach on this fixture (the host default and a figure
above the whole present corpus), and the round is only readable if the env rung
at the matching budget and the `-m` rung agree.

WHAT A RUNG IS WORTH READING FROM. Not the totals. Each window prints its own
`ntt syndromes (m=.., needed=.., n=<sources in THAT window>, W=.., threads=..):
<time>`, so a rung with k windows hands back k points of `(S, t)` in ONE leg -
which is how section 8.5 fitted both constants of `c_l * S + c_w * m` from a
single host leg. Pooled across the ladder those points are the answer: if `c_l`
is a constant they lie on one line whatever the rung, and if
`NTT_WINDOW_COMBINE_X86`'s own 16 Sep docstring is right that "a transform over
1,040 sources is not the same transform per source as one over 7,900", they do
not, and the departure IS the finding. Every point is recorded
(`win_points`), not just the rung's sum.

THE BOTTOM OF THE LADDER FOLDS, AND THAT IS A FINDING. `ntt_window_row_ask`
asks `gate + gate * k / (S - k)` rows of a window holding S sources (`gate` =
`ntt_min_missing`, 256 on the nibble class; `k` = `NTT_WINDOW_COMBINE_X86` =
312), so the ask RISES as the window narrows and at some rung the corpus is
refused the transform and the leg folds. Size the rungs to reach that edge
deliberately: a folded leg is the row gate working, it ends the ladder, and it
prices what the gate hands back at its own crossover. `path` in each leg record
says which was taken.

RUNGS are given as `label=spec` in `RUNGS`, comma-separated, spec one of:
    <bytes>   NZBFAST_NTT_BUDGET=<bytes>, the instrument
    m<MiB>    `parfast r -m<MiB>`, a control (moves the solve window too)
    host      no budget argument at all, the host default (RAM/4)
any of which may carry `+M<int>`, which pins THAT RUNG'S OWN `m` (the damage
count) instead of the round's global `M` - the 16 Sep 2026 extension that makes
this driver ladder `m` as well as the window count, for section 8.12 - or `+f`, which sets `NZBFAST_NTT=force` for that rung so the
transform runs at a budget `auto` REFUSES - the only way to price what the row
gate hands back when it folds, rather than extrapolating it - or `+r<bytes>`,
which pins `NZBFAST_REPAIR_RETAIN` for that rung. THAT IS A SECOND CONFOUND'S CONTROL, not decoration: `retain.rs`'s verify-
pass cache falls back to the SAME `ntt_budget_within_published`, so a rung that
lowers the NTT budget also shrinks the cache and hands the feed more present
blocks to READ a second time. The transform's own `ntt syndromes` times are
immune to that - they time the transform call and nothing else, which is why
the ladder fit is taken on them - but a rung's WALL and CPU are not, so at
least one rung should be run again with the cache pinned high to price it.

RUN:
    BIN=/path/parfast BIN_AA=/path/parfast_aa SCRATCH=/dir M=1400 \
    SLICE=4194304 SEED=2001 THREADS=8 REPS=2 \
    RUNGS='w1=16777216000,w2=7969177600,...,ctl_host=host,ctl_m16=m16000' \
    [MARG=14000] [FIX=fix] [TAG=x] [OUT=legs.jsonl] [STRAYS=1] nttladder.py

`ARENA_PROBE=1` SPENDS TWO LEGS MEASURING THE ARENA TERM BEFORE THE LADDER
PROPER, and prints what every rung will actually do with it (17 Sep 2026, item
3 of an internal note). A rung is a
budget and the sources it buys a window is `(budget - arenas) / block_size`,
so the rung spacing is only as good as the arena figure - and the two ways of
getting that figure without measuring it are both on the record as errors of
16 MiB and 59%, the second GROWING WITH `m`, which on an m-ladder is the axis
under measurement. The probe reads `arenas = budget - S_first * blocksize` off
one leg at each end of the round's own `m` range, fits the line, and then
prints an `ARENA-FIT`, an `ARENA-SCALED-WOULD-BE` pricing what the probe just
bought on THIS round's numbers, and one `PREDICT` line per rung giving its
first-window width, its window count and whether it leaves a REMAINDER window
- which costs about half a full one (8.16.5) and skewed 8.11's headline until
8.16 re-measured it. All of that is BEFORE the rig is spent, which is section
8.17's "ask the plan before you ask the clock" applied to the one quantity
that rule had not reached. Probe legs are banked in `<OUT>.probe.jsonl`, never
in `OUT`, so no reducer's population gains two legs no rung asked for; and
every leg, probed or not, now records its own realised `arenas`, so a banked
round can be re-checked later without re-running anything.

A rung spelt `k<int>` NAMES THE WINDOW COUNT IT WANTS instead of the budget
that buys it, and the driver computes that budget from the measured line -
`ceil(present / k)` sources a window, plus `ARENA_HEADROOM_BLOCKS` (0 by
default). It needs `ARENA_PROBE=1` and is refused at STARTUP without it.
**A rung that names BYTES is reported on and never rewritten**, and that is
deliberate rather than timid: there is no single placement policy to bake in.
8.18's own k = 2 rung at m = 1,000 split 9,200 present sources as [5704,
3496] - 62/38, not the even 4,600 `ceil(present / k)` asks for - so a driver
that quietly "corrected" budgets would have moved that round's windows and
measured a different cell than the one banked. The even split is available by
asking for it in as many words, where the policy is visible in this file and
on the `RUNG-BUDGET` line.

UNSET, EVERY ONE OF THESE CHANGES NOTHING. No probe runs, no `ARENA` line is
printed, and the `RUNGS` line keeps the five-element shape that 8.11 through
8.18 produced, so those logs stay reproducible byte for byte by the
invocations that produced them and no reducer meets a new field.
`nttladder_smoke.py` asserts exactly that, and asserts the other direction too
by planting a known `arenas(m)` in its stub engine and requiring the fit to
recover it from two probe legs alone.

`MARG` pins `-m` on every rung that is not itself a `-m` control, so an
`m`-ladder's rising solve window cannot cross the published limit partway up
and start slabbing. `STRAYS=1` deletes the repair's `<member>.N` backup copies
after every leg, which otherwise accumulate one set per leg and fill the box
(section 8.13.9); the keep set is the work directory as the round found it. Reduce an `m`-ladder with `nttmsum.py`, not `nttladsum.py`:
the latter's fit assumes the leaf term is the same at every rung, which is true
only while `m` is held.

PLACE THE RUNGS ON THE MEASURED ARENA TERM, NOT ON A CODE-DERIVED ONE. A rung
is a budget, and the sources it buys a window is `(budget - arenas) /
block_size`, so the rung spacing is only as good as the arena figure. Deriving
it from `FlatPlan::scratch_bytes(m, W) * 8` overstates it: section 8.16.2 of
an internal note measured the term at
**140,664,832 B** at m = 1,400 / W = 512 where that arithmetic gives
**157,442,048** - 16 MiB, which is four sources a window at 4 MiB blocks. That
is why every rung of section 8.11's ladder landed 4 sources wider than its own
arithmetic predicted, and why its deepest rung split as 9 x 404 + a 64 rather
than into ten even windows - a REMAINDER window, which costs about half a full
one (8.16.5) and skewed that section's headline figure until 8.16 re-measured
it. ONE PROBE LEG FIXES IT: run any rung, read the first window's source count
out of its own `ntt syndromes` line, and take `arenas = budget -
S_first_window * block_size`. Then place the ladder. The reducer
`nttladsum.py` now classifies remainders and sets them aside, so a round that
produces one is still readable - but a rung that splits evenly measures the
window count it is named for, and one that does not measures something else.

FIXTURE: section 8.2's, unchanged and for its reasons - 20 x 1,020 MiB of
urandom, 4 MiB blocks, 5,100 source + 1,650 recovery, m = 1,400 damaged. At
that `m` the solve window is 2 * 1400 * 4 MiB = 11,200 MiB, UNDER this box's
RAM/4 = 11,989, so both the solve slab count and the stripe are pinned at every
rung and only the window count moves. Build it with `head -c`, never
`dd bs=1M count=N` from a pipe - a short read counts as a whole block and
section 8's fixture was built twice for it - and ASSERT the member size.

Every leg is SHA-256 gated against the pristine members and restored by slice;
a leg that is not byte-exact is damage and not data and the driver stops.
`pdrv.run_leg` quiet-gates each leg and records foreign CPU either side plus
/proc/stat steal; /proc/vmstat pswpin/pswpout are read across each leg.

THIS DRIVER RUNS ON WINDOWS SINCE 17 Sep 2026, and nothing in it changed to
make that true - the whole port is in `pdrv.py` and `winproc.py` beside it
(claim `nttladder-windows-port-17sep`). It matters because both of this
fleet's bare-metal `KernelClass::Avx512Gfni` parts ARE Windows, so sections
8.13.2 and 8.18 each had to take their GFNI cell to a KVM guest, where 8.18
measured hypervisor steal displacing a fitted knee by 20%. TWO FIELDS COME
BACK EMPTY THERE AND BOTH ARE HONEST: `swap_in_pages` / `swap_out_pages` are
`null`, because `/proc/vmstat` has no Windows equivalent this driver reads;
and `steal_pct` is `n/a`, because steal exists only under virtualisation - on
windows-gaming-pc-b or amd-ryzen-9800x3d that absence IS the reason the round is being run there, and
`n/a` rather than 0.0 keeps it from being quoted as a measured zero.
`harness/nttladder_smoke.py` runs this file end to end against a stub
tool in seconds, on any platform, and is how a change here is checked without
a rig.
ONE damage seed for the WHOLE round, for the reason bareraise.py's header
gives: the slab plan is computed from the damage PATTERN, so a per-rep seed
makes each rep a different cell, silently.

ASK THE PLAN BEFORE YOU ASK THE CLOCK (17 Sep 2026, section 8.17). Not every
question on this axis needs a rung, and two rounds have paid a rig for one that
did not. A `FlatPlan`'s LEAF FILL - how full each leaf is, and therefore which
of the three leaf kernels it is admitted to - is a property of the present set
and `needed` and of NOTHING ELSE: not the block size, not the thread count, not
the box. `NZBFAST_NTT_FILL=1` logs it as one `[ntt-fill]` line per plan
(`FlatPlan::report_leaf_fill`), carrying the live leaf count, the fill's min,
median and max and the dense/paired/additive split. So the whole
window-width-to-kernel mapping is UNTIMED, and can be taken on a 128 MiB
fixture on a loaded laptop while the rig is busy with something that needs it.
Section 8.15 spent a 46 GiB fixture and about 4.4 hours of rig lock bracketing
a saturation whose LOCATION was free this way, and reported it as a
14,000-to-22,000 band that was really a 900-source knee; 8.17 took the location
off a laptop and used the rig only to show the clock agreed. Before sizing a
cell here, ask whether the quantity is a property of the PLAN rather than of
the run. an internal note is a working census
and `leafsum.py` beside it pairs each window's `[ntt-fill]` line to its own
`(S, t)`.

AND THE THREE ARMS THAT NEED NO DRIVER CHANGE. `pdrv.run_leg` overlays
`env_extra` onto a copy of `os.environ`, so any knob read once from the
environment can be moved for a WHOLE ROUND by exporting it around this driver -
no rung syntax, no edit here, and no `website/parfast-bench` regeneration.
Section 8.17 ran `NZBFAST_NTT_ADDITIVE=0` and `NZBFAST_NTT_ADDITIVE_MIN=64` as
whole-round arms exactly that way, against an unchanged copy of this file.

ONE SEED IS NOT ONE PLAN ONCE THE RUNGS CARRY `+M`, and that is a real
difference from the 8.11 round rather than a relaxation of its rule. A damage
plan IS a count of damaged slices, so an `m`-ladder's rungs MUST differ in it;
what the one seed still buys is that every leg at a given `m` - both A/A arms,
every rep, and the `k = 1` and `k = 2` rungs that are differenced against each
other to read the per-window charge - repairs byte-identical damage. Plans are
memoised per `m` and each one is printed as a `PLAN` line when it is first
built, so the log says how many plans a round had.
"""
import json
import math
import os
import re
import subprocess  # noqa: F401  (pdrv's child plumbing; kept for parity)
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
SLICE = int(os.environ.get("SLICE", "4194304"))
M = int(os.environ.get("M", "1400"))
REPS = int(os.environ.get("REPS", "2"))
# `REP0` offsets the rep NUMBERING (reps run REP0+1 .. REP0+REPS), so a second
# sitting over a SUBSET of the rungs - "two reps on the rungs carrying the
# claim", which is the usual shape of a long round split across rig locks - is
# a distinct rep to every reducer rather than a silent second copy of rep 1
# that the A/A pairing would collapse. Unset, numbering starts at 1 as before.
REP0 = int(os.environ.get("REP0", "0"))
SEED = int(os.environ.get("SEED", "2001"))
THREADS = os.environ.get("THREADS", "8")
# `MARG` appends `-m<MARG>` to EVERY rung that does not carry its own `-m`
# control (16 Sep 2026, with the m-ladder). An `m`-ladder raises the SOLVE
# window 2*m*blocksize rung by rung, so a round that leaves the published limit
# at the host default crosses it partway up and starts SLABBING - which is
# section 8.7's OTHER count, and a rung that slabs is not on the same ladder as
# one that does not. Pinning the limit once, above every rung's solve window,
# holds the solve plan at ONE slab by construction instead of by luck. Unset -
# every pre-16-Sep invocation - changes nothing.
MARG = os.environ.get("MARG")
TAG = os.environ.get("TAG", "")
# `STRAYS=1` deletes the repair's leftover `<member>.N` backup copies after
# every leg (17 Sep 2026, with the NEON m-ladder). parfast backs up each
# damaged original BEFORE it writes, and without `-p` - which also deletes the
# recovery volumes, so it is not available to a round that repairs the same set
# eighty times - those copies accumulate one SET PER LEG: `.1`, then `.2`, then
# `.3`. Section 8.13.9 measured 13.7 GiB a leg and a 54-leg ladder filling that
# box around leg six. The keep set is the work directory's contents as the
# round FOUND them, snapshotted before the first leg, so the members and every
# `set.volNNN+NN.par2` survive by construction rather than by a glob that has
# to be right. Unset - every invocation written before this date - changes
# nothing.
STRAYS = os.environ.get("STRAYS") == "1"
# `ARENA_PROBE=1` spends TWO LEGS measuring the arena term before the ladder
# proper (17 Sep 2026, item 3 of
# an internal note). Unset - every
# invocation written before this date - changes nothing at all: no probe runs,
# no line is printed, and `k` rungs are refused at startup.
ARENA_PROBE = os.environ.get("ARENA_PROBE") == "1"
# Blocks of slack added to a `k` rung's computed budget. ZERO by default, and
# that default is a statement: a budget is placed on a MEASURED term now, so
# padding it is a decision a lane takes deliberately and sees in the log,
# never one the driver takes for it.
ARENA_HEADROOM_BLOCKS = int(os.environ.get("ARENA_HEADROOM_BLOCKS", "0"))
OUT = os.path.join(S, os.environ.get("OUT", "legs.jsonl"))
LOGDIR = os.path.join(S, "legs")
os.makedirs(LOGDIR, exist_ok=True)

MULT = {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}


def parse_rungs(spec):
    """`label=spec` pairs -> (label, env_budget|None, m_arg|None, retain|None,
    m|None, k|None).

    THE SIXTH ELEMENT IS NEW (17 Sep 2026, handoff item 3) AND COSTS NOTHING
    TO A ROUND THAT DOES NOT USE IT. A rung spelt `k<int>` names the WINDOW
    COUNT it wants instead of the budget that buys it, and its budget is
    computed after the arena probe below from a MEASURED arena term. Every
    other spelling parses exactly as it did, carries `k = None`, and - see
    `__main__` - is printed on the `RUNGS` line in the five-element shape
    every invocation from 8.11 through 8.18 produced, so no banked log and no
    reducer sees a new field because of this.
    """
    out = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        label, _, val = item.partition("=")
        # `+M<int>` pins THIS rung's damage count, the 16 Sep 2026 m-ladder
        # extension. Absent - which is every rung of the 8.11 round and of
        # anything written against this driver before that date - the rung
        # takes the round's global `M` and the behaviour is unchanged. Strip
        # it FIRST so the `+f` and `+r` suffixes parse exactly as they did.
        mm = re.search(r"\+M(\d+)", val)
        rung_m = int(mm.group(1)) if mm else None
        val = re.sub(r"\+M\d+", "", val)
        force = val.endswith("+f")
        if force:
            val = val[:-2]
        val, _, ret = val.partition("+r")
        retain = int(ret) if ret else None
        if force:
            retain = ("force", retain)
        if val == "host":
            out.append((label, None, None, retain, rung_m, None))
        elif val.startswith("m"):
            out.append((label, None, val[1:], retain, rung_m, None))
        elif val.startswith("k"):
            # `k<int>`: the window count this rung wants. Needs ARENA_PROBE,
            # and the driver refuses at startup rather than part way up a
            # ladder if it is missing - a rung whose budget cannot be computed
            # is not a rung that should be discovered at leg one.
            out.append((label, None, None, retain, rung_m, int(val[1:])))
        else:
            out.append((label, int(val), None, retain, rung_m, None))
    return out


RUNGS = parse_rungs(os.environ["RUNGS"])

KEEP = frozenset(os.listdir(WORK))
members = sorted(f for f in os.listdir(PRISTINE) if f.endswith(".bin"))
gold = {}
for line in open(os.path.join(S, FIX, "gold.sha")):
    h, name = line.split()
    gold[name.lstrip("*")] = h


def vmstat_pages():
    try:
        out = {}
        for line in open("/proc/vmstat"):
            k, _, v = line.partition(" ")
            if k in ("pswpin", "pswpout"):
                out[k] = int(v)
        return (out["pswpin"], out["pswpout"])
    except Exception:
        return None


def _sec(value, unit):
    return round(float(value) * MULT[unit], 4)


def dispatch(errpath):
    """The decision the leg took AND the per-window points it produced.

    bareraise.py's `dispatch` records the window COUNT; this one records each
    window's own `(S, t)`, because the count alone cannot tell a per-window
    charge that is flat from one that moves with the window's width. The tail
    window prints an `ntt syndromes` line and no `ntt window` line, so the
    syndrome lines ARE the windows and `ntt window` undercounts by one - the
    same trap bareraise.py documents; both are kept.
    """
    err = open(errpath, errors="replace").read()
    slabs = re.search(r"in (\d+) slab\(s\) of (\d+) B", err)
    syn = re.findall(
        r"ntt syndromes \(m=(\d+), needed=(\d+), n=(\d+), W=(\d+), threads=(\d+)\): "
        r"([0-9.]+)(ns|µs|us|ms|s)",
        err,
    )
    win = re.findall(
        r"ntt window \((\d+) bytes, (\d+) slices, (\w+)\): ([0-9.]+)(ns|µs|us|ms|s)", err
    )

    def term(pat):
        mm = re.search(pat + r": \+?([0-9.]+)(ns|µs|us|ms|s)", err)
        return _sec(mm.group(1), mm.group(2)) if mm else None

    def total(pat):
        hits = re.findall(pat + r": \+?([0-9.]+)(ns|\u00b5s|us|ms|s)", err)
        return round(sum(_sec(v, u) for (v, u) in hits), 3) if hits else None

    points = [
        {"n": int(n), "t": _sec(v, u), "W": int(w), "threads": int(th), "needed": int(nd)}
        for (_m, nd, n, w, th, v, u) in syn
    ]
    return {
        "path": "ntt" if syn else "fold",
        "slabs": int(slabs.group(1)) if slabs else 1,
        "slab_width": int(slabs.group(2)) if slabs else SLICE,
        "ntt_syn_calls": len(points),
        "ntt_windows": len(win),
        "ntt_window_states": [st for (_, _, st, _, _) in win],
        "win_points": points,
        "win_sources": sum(p["n"] for p in points),
        "syn_total": round(sum(p["t"] for p in points), 3),
        "ntt_w": sorted({p["W"] for p in points}),
        "feed_fold_solve": term(r"feed\+fold\+solve"),
        "final_verify": term(r"final verify"),
        "patch": term(r"\bpatch"),
        "back_sub": total(r"back-substitution \([^)]*\)"),
        "verify_targets": term(r"verify targets \+ volume scan"),
        "load_recovery": term(r"load recovery"),
    }


# ---------------------------------------------------------------------------
# THE ARENA TERM, MEASURED RATHER THAN DERIVED
# ---------------------------------------------------------------------------
# A rung is a BUDGET, and the sources it buys a window is
# `(budget - arenas) / block_size` - so the rung spacing is only ever as good
# as the arena figure, and every lane has been deriving that figure by hand.
# Two ways of getting it wrong are already on the record:
#
#   - FROM THE CODE. `FlatPlan::scratch_bytes(m, W) * 8` overstates it.
#     Section 8.16.2 measured 140,664,832 B at m = 1,400 / W = 512 where that
#     arithmetic gives 157,442,048 - 16 MiB, four sources a window at 4 MiB
#     blocks. That is why every rung of 8.11's ladder landed four sources
#     wider than its own arithmetic predicted, and why its deepest rung split
#     as 9 x 404 + a 64 rather than into ten even windows.
#   - BY SCALING ONE MEASUREMENT. 8.13's single 101,081,088 B at m = 920,
#     scaled linearly in `m`, predicts 618 MiB at m = 5,900 where the measured
#     term is 388.2 MiB - 59% high. 8.14.9 found the same class of error on
#     NEON. THE ERROR GROWS WITH `m`, which on an m-ladder is the axis under
#     measurement, so a ladder carrying a closed form displaces its own
#     windows by an amount correlated with its own abscissa.
#
# Two legs settle it. The arena term is a LINE in `m` - 8.18.3 measured
# `arenas(m) = 60,652 * m + 49.2 MB` on the GFNI class at both ends of the
# axis - so one leg at each end of the round's own `m` range determines it.
#
# THE ARITHMETIC IS NOT GUESSED. It was re-derived from 8.18's own banked
# probe legs (an internal note)
# while this was written, and it reproduces that section's published figures:
#   m=1,000, budget 6,090,948,251, split [5704, 3496]
#       -> arenas = 6,090,948,251 - 5704 * 1 MiB = 109,870,747 (8.18: 104.8 MiB)
#   m=5,900, budget 3,443,741,028, split [2896, 1404]
#       -> arenas = 3,443,741,028 - 2896 * 1 MiB = 407,064,932 (8.18: 388.2 MiB)
#   slope (407,064,932 - 109,870,747) / 4,900 = 60,651.9   (8.18: 60,652)
#   intercept 109,870,747 - 60,651.9 * 1,000 = 49,218,847  (8.18: 49.2 MB)
# and `sum(n)` over a probe's windows is 9,200 at m = 1,000 and 4,300 at
# m = 5,900 against a 10,200-block source set, which is what establishes that
# a window holds the PRESENT sources, `src_blocks - m`, and not all of them.
#
# WHAT THIS DELIBERATELY DOES NOT DO: SYNTHESISE A BUDGET FOR A RUNG THAT
# NAMED ONE. A raw-byte rung is left exactly alone, and that is not caution,
# it is that THERE IS NO SINGLE PLACEMENT POLICY TO BAKE IN. 8.18's own k = 2
# budget at m = 1,000 split 9,200 present sources as [5704, 3496] - 62/38, not
# the even 4,600 that `ceil(S / k)` would ask for - so a driver that quietly
# recomputed budgets "correctly" would have moved that round's windows and
# measured a different cell than the one banked. A lane's placement is a
# judgement. What the driver can do without taking that judgement away is
# MEASURE the term, PREDICT what each rung will actually do with it, and say
# so before the rig is spent; a rung that wants the even split asks for it in
# as many words with `k<int>`, where the policy is visible in this file and in
# the log rather than implied.
def _arena_of(rec):
    """`arenas = budget - S_first * blocksize` for one probe leg, or None.

    Only a rung that NAMED a budget can say anything: a `host` rung's budget
    is RAM/4 inside the engine and never appears in the record, and an `-m`
    control moves the solve window too. Refusing to answer is right; guessing
    the host default from this side is how a closed form gets re-derived.
    """
    if rec.get("ntt_budget") is None or not rec.get("win_points"):
        return None
    return rec["ntt_budget"] - rec["win_points"][0]["n"] * SLICE


def arena_fit(points):
    """[(m, arenas)] -> (slope, intercept, note).

    Two or more distinct `m` give the line. ONE gives a CONSTANT and says so
    rather than reporting a slope of zero as if it had been measured - the
    whole error class this exists to close is a slope taken on faith.
    """
    ms = sorted({m for m, _ in points})
    if not points:
        return None, None, "no probe leg produced a readable arena term"
    if len(ms) < 2:
        return 0.0, float(points[0][1]), (
            "ONE m only (%d) - the intercept is measured and the SLOPE IS NOT. "
            "Read any prediction at another m as unfounded." % ms[0])
    lo = min(points, key=lambda p: p[0])
    hi = max(points, key=lambda p: p[0])
    slope = (hi[1] - lo[1]) / float(hi[0] - lo[0])
    return slope, lo[1] - slope * lo[0], "two ends of the m axis, %d and %d" % (lo[0], hi[0])


def arena_pass(picks_for):
    """Measure the arena term, then say what every rung will actually do.

    Runs TWO probe legs - the extremes of the round's own `m` axis - before
    the ladder proper, banks them in `<OUT>.probe.jsonl` (never in `OUT`; see
    `run_leg`), fits `arenas(m)`, resolves any `k<int>` rung into a budget,
    and prints one PREDICT line per rung saying how that rung's budget will
    split. Returns the rung list to actually run.

    IT PREDICTS EVERY RUNG AND SYNTHESISES ALMOST NONE OF THEM. See the block
    comment above `_arena_of` for why: a lane's budget placement is a
    judgement (8.18's own k = 2 rung is a 62/38 split, not an even one), so a
    raw-byte rung is reported on and left alone. The point is that a lane sees
    the split BEFORE the rig is spent rather than reading it out of the first
    leg's stderr afterwards - which is section 8.17's own rule, "ask the plan
    before you ask the clock", applied to the one quantity that rule had not
    reached.

    THE PROBES ARE REAL LEGS AND COST WHAT A LEG COSTS. On 8.18's cell that
    is about 9-14 s each. They are run with the `a` binary only and are not
    paired A/A, because nothing is being compared: the quantity read off them
    is an allocation size, which does not have a noise floor.
    """
    print("ARENA-PROBE on (ARENA_PROBE=1)", flush=True)
    budgeted = [r for r in RUNGS if r[1] is not None]
    if not budgeted:
        raise SystemExit(
            "ARENA_PROBE=1 needs at least one rung that NAMES a budget to probe "
            "with - a `host` rung's budget is RAM/4 inside the engine and never "
            "reaches the log, and an `-m` control moves the solve window too. "
            "Give the probe something to read.")
    by_m = {}
    for r in budgeted:
        by_m.setdefault(M if r[4] is None else r[4], r)
    probe_ms = sorted(by_m)
    probes = [by_m[probe_ms[0]]] if len(probe_ms) == 1 else [by_m[probe_ms[0]], by_m[probe_ms[-1]]]
    probe_out = OUT + ".probe.jsonl"

    points, src_blocks = [], {}
    for (rung, budget, marg, retain, rung_m, _k) in probes:
        mm = M if rung_m is None else rung_m
        rec = run_leg(0, "probe-" + rung, budget, marg, retain, "a", BIN,
                      picks_for(mm), 0, mm, out_path=probe_out)
        if rec["path"] != "ntt":
            raise SystemExit(
                "probe rung %s FOLDED (path=%s) - it took the fold path, so it "
                "printed no window and there is no arena term to read off it. "
                "Probe with a rung the row gate admits." % (rung, rec["path"]))
        arenas = rec["arenas"]
        if arenas is None:
            raise SystemExit("probe rung %s produced no readable arena term" % rung)
        # sum(n) over a probe's windows is the PRESENT sources, so the source
        # set size is that plus the damage count. Both probes must agree on it
        # - they are the same fixture - and a disagreement means one of them
        # is not measuring the set the other is, which is a stop and not a
        # warning.
        src_blocks[mm] = rec["win_sources"] + mm
        points.append((mm, arenas))
        print("ARENA m=%d budget=%d S_first=%d arenas=%d (%.1f MiB) "
              "present=%d src_blocks=%d"
              % (mm, budget, rec["win_points"][0]["n"], arenas,
                 arenas / float(1 << 20), rec["win_sources"], src_blocks[mm]),
              flush=True)
    if len(set(src_blocks.values())) > 1:
        raise SystemExit(
            "the probe legs disagree about the source set size: %s. They are "
            "the same fixture, so one of them is not measuring what the other "
            "is - stop and find out which before spending the ladder."
            % src_blocks)
    blocks = list(src_blocks.values())[0]

    slope, intercept, note = arena_fit(points)
    print("ARENA-FIT arenas(m) = %.1f * m + %.0f   (%s)" % (slope, intercept, note),
          flush=True)
    if len(points) > 1:
        # The closed form this replaces, priced on THIS round, so the log says
        # what the probe was worth rather than quoting 8.13's 59%.
        lo_m, lo_a = min(points, key=lambda q: q[0])
        hi_m, hi_a = max(points, key=lambda q: q[0])
        scaled = lo_a * (hi_m / float(lo_m)) if lo_m else 0.0
        print("ARENA-SCALED-WOULD-BE %.0f at m=%d against %.0f measured "
              "(%+.1f%%, %+d sources a window at this block size) - this is what "
              "the two probe legs bought"
              % (scaled, hi_m, hi_a, (scaled / hi_a - 1.0) * 100.0,
                 int((scaled - hi_a) // SLICE)), flush=True)

    def arenas_at(mm):
        return slope * mm + intercept

    out = []
    for (rung, budget, marg, retain, rung_m, k) in RUNGS:
        mm = M if rung_m is None else rung_m
        present = blocks - mm
        if k is not None:
            # THE EVEN SPLIT, STATED. `ceil(present / k)` sources in every
            # window, which is the placement that produces k windows with the
            # smallest remainder available at that k. A lane that wants a
            # different split names bytes instead; that is the whole reason
            # this is opt-in.
            per = -(-present // k)
            budget = int(math.ceil(arenas_at(mm))) + (per + ARENA_HEADROOM_BLOCKS) * SLICE
            print("RUNG-BUDGET %s k=%d m=%d present=%d per_window=%d "
                  "headroom_blocks=%d -> budget=%d"
                  % (rung, k, mm, present, per, ARENA_HEADROOM_BLOCKS, budget), flush=True)
        if budget is None:
            print("PREDICT %-12s m=%-5d (no budget named - host default or an -m "
                  "control; nothing to predict)" % (rung, mm), flush=True)
            out.append((rung, budget, marg, retain, rung_m, k))
            continue
        room = budget - arenas_at(mm)
        s_first = int(room // SLICE)
        if s_first < 1:
            raise SystemExit(
                "rung %s (m=%d) has a budget of %d against a measured arena term "
                "of %.0f - that buys ZERO sources a window and the rung cannot "
                "run. Re-place it on the fitted line above."
                % (rung, mm, budget, arenas_at(mm)))
        wins = -(-present // s_first)
        tail = present - s_first * (wins - 1)
        flag = ""
        if wins > 1 and tail != s_first:
            # A REMAINDER WINDOW COSTS ABOUT HALF A FULL ONE (8.16.5) and
            # skewed 8.11's headline figure until 8.16 re-measured it.
            # `nttladsum.py` classifies and sets them aside, so a round that
            # produces one is still readable - but a rung that splits evenly
            # measures the window count it is named for and one that does not
            # measures something else, so it is said out loud HERE, before the
            # rig is spent, rather than found in reduction afterwards.
            flag = "  REMAINDER tail=%d of %d - this rung does not split evenly" % (tail, s_first)
        print("PREDICT %-12s m=%-5d present=%-6d budget=%-13d S_first=%-6d windows=%d%s"
              % (rung, mm, present, budget, s_first, wins, flag), flush=True)
        out.append((rung, budget, marg, retain, rung_m, k))
    print("ARENA-PROBE done - %d probe leg(s) banked in %s"
          % (len(points), os.path.basename(probe_out)), flush=True)
    return out


def run_leg(rep, rung, budget, marg, retain, label, exe, picks, order, rung_m,
            out_path=None):
    """`out_path` sends a leg's record somewhere other than `OUT`. It exists
    for the arena probe, whose legs are MEASUREMENT OF THE BOX and not rungs
    of the ladder: banking them in `OUT` would put two legs into every
    reducer's population that no rung asked for, and 8.18 kept them apart by
    hand in a separate invocation (`legs-probe.jsonl` beside
    `legs-ladder.jsonl`). Default unchanged.
    """
    argv = ["r", "-t" + THREADS, "-q"]
    if marg is not None:
        argv.append("-m" + marg)
    elif MARG:
        argv.append("-m" + MARG)
    argv.append("set.par2")
    env = {"NZBFAST_REPAIR_TIMING": "1"}
    if budget is not None:
        env["NZBFAST_NTT_BUDGET"] = str(budget)
    if isinstance(retain, tuple):
        env["NZBFAST_NTT"] = "force"
        retain = retain[1]
    if retain is not None:
        env["NZBFAST_REPAIR_RETAIN"] = str(retain)
    tag = "%s-%s-r%d%s" % (rung, label, rep, ("-" + TAG) if TAG else "")
    logbase = os.path.join(LOGDIR, tag)
    pdrv.apply_damage(WORK, members, SLICE, picks, 1)
    sw0 = vmstat_pages()
    res = pdrv.run_leg(exe, argv, WORK, logbase, env_extra=env)
    sw1 = vmstat_pages()
    # `pdrv.gate` returns (good, bad), NOT a bool - `rc == 0 and pdrv.gate(...)`
    # is true for every value it can return. Unpack it.
    _good, bad = pdrv.gate(WORK, members, gold)
    ok = res["rc"] == 0 and not bad
    pdrv.restore_slices(WORK, PRISTINE, members, SLICE, picks)
    _good, bad_after = pdrv.gate(WORK, members, gold)
    if bad_after:
        raise SystemExit("restore failed at %s: %s" % (tag, bad_after))
    strays = pdrv.remove_strays(WORK, KEEP) if STRAYS else 0
    rec = dict(res)
    rec.update(dispatch(logbase + ".err"))
    rec.update({
        "tag": TAG, "m": rung_m, "slice": SLICE, "rep": rep, "rung": rung, "arm": label,
        "bin": exe, "ntt_budget": budget, "m_arg": marg, "retain": retain,
        "threads": int(THREADS), "marg": marg or MARG,
        "ok": ok, "bad": bad, "order": order, "strays_removed": strays,
        "swap_in_pages": (sw1[0] - sw0[0]) if (sw0 and sw1) else None,
        "swap_out_pages": (sw1[1] - sw0[1]) if (sw0 and sw1) else None,
        "utc": pdrv.utcnow(),
    })
    # The realised arena term for THIS leg, from this leg's own first window.
    # Recorded on every leg and not only on a probe, because it is free here
    # and it is what lets a banked round be re-checked later without re-running
    # anything - a rung that landed on a different arena term than its
    # neighbours is a rung that measured something else. `null` on a rung that
    # named no budget, which is the only honest answer there.
    rec["arenas"] = _arena_of(rec)
    with open(out_path or OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-22s rc=%d ok=%s wall=%8.2f cpu=%9.2f peak=%7.1fMB slabs=%d path=%-4s "
          "wins=%d syn=%7.2f n=%s swap=%s/%s fgn=%.1f/%.1f steal=%s"
          % (tag, rec["rc"], ok, rec["wall"], rec["cpu"], rec["peak_mb"], rec["slabs"],
             rec["path"], rec["ntt_syn_calls"], rec["syn_total"],
             [p["n"] for p in rec["win_points"]], rec["swap_in_pages"], rec["swap_out_pages"],
             rec["foreign_cpu"], rec["foreign_after"], rec["steal_pct"]),
          flush=True)
    if not ok:
        raise SystemExit("NOT byte-exact at " + tag + " - that is damage, not data")
    return rec


if __name__ == "__main__":
    _good, bad = pdrv.gate(WORK, members, gold)
    if bad:
        raise SystemExit("work copy is not pristine at start: %s" % bad)
    print("BIN   %s" % json.dumps(pdrv.bin_facts([BIN, BIN_AA]), sort_keys=True), flush=True)
    print("BOX   %s" % json.dumps(pdrv.box_facts(), sort_keys=True), flush=True)
    print("SHAPE m=%d slice=%d solve_window=%d MiB reps=%d threads=%s marg=%s"
          % (M, SLICE, 2 * M * SLICE // (1 << 20), REPS, THREADS, MARG), flush=True)
    # THE `RUNGS` LINE KEEPS ITS FIVE-ELEMENT SHAPE unless a rung actually
    # carries a `k`, so every log 8.11 through 8.18 produced is reproducible
    # byte for byte by the invocation that produced it, and no reducer meets a
    # field it has not seen. A round that opts in gets the sixth element and a
    # second, resolved line below.
    _has_k = any(r[5] is not None for r in RUNGS)
    print("RUNGS %s" % json.dumps([list(r) if _has_k else list(r[:5]) for r in RUNGS]),
          flush=True)
    print("SEED  %d (one plan for every rep and every rung)" % SEED, flush=True)
    if _has_k and not ARENA_PROBE:
        raise SystemExit(
            "a `k<int>` rung needs ARENA_PROBE=1: its budget is computed from a "
            "MEASURED arena term and there is nothing to compute it from. "
            "Refusing at startup rather than at leg one.")
    t0 = time.monotonic()
    # ONE SEED for the whole round, but NOT one plan when the rungs carry
    # their own `m`: a plan IS a count of damaged slices, so an m-ladder's
    # rungs differ by construction. Memoised per m, so every rung at a given
    # m - and every rep and both A/A arms - repairs byte-identical damage.
    _picks = {}

    def picks_for(mm):
        if mm not in _picks:
            _picks[mm] = pdrv.damage_picks(WORK, members, SLICE, mm, SEED)
            print("PLAN  m=%d slices=%d over %d member(s)"
                  % (mm, sum(len(v) for v in _picks[mm]["bym"].values()),
                     len(_picks[mm]["bym"])), flush=True)
        return _picks[mm]

    RUNGS_RUN = RUNGS
    if ARENA_PROBE:
        RUNGS_RUN = arena_pass(picks_for)

    for rep in range(REP0 + 1, REP0 + REPS + 1):
        # Rotated by rep and reversed on even reps, like bareraise.py: no rung
        # keeps the same neighbours and none keeps the cold-cache first slot.
        rot = (rep - 1) % max(len(RUNGS_RUN), 1)
        order = RUNGS_RUN[rot:] + RUNGS_RUN[:rot]
        if rep % 2 == 0:
            order = list(reversed(order))
        for i, (rung, budget, marg, retain, rung_m, _k) in enumerate(order):
            mm = M if rung_m is None else rung_m
            picks = picks_for(mm)
            arms = [("a", BIN), ("a_aa", BIN_AA)]
            if (rep + i) % 2 == 1:
                arms = list(reversed(arms))
            for label, exe in arms:
                run_leg(rep, rung, budget, marg, retain, label, exe, picks, i, mm)
    print("ALL DONE in %.0f s" % (time.monotonic() - t0), flush=True)
