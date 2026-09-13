#!/usr/bin/env python3
"""jcross.py - where does `parfast --fast` stop paying, per kernel class?

THE QUESTION HAS MOVED SINCE THE 10 SEP ROUNDS, and a round that does not
notice measures a binary nobody ships.

an internal note reports the whole joint
arm winning 9-40% from m = 8,192 up to 29,484 and "turning over below
about m = 8,000". That was measured with BOTH stages moving together. On
11 Sep 2026 the two stages were split (`316f12ffb3`): stage 1 is gated on
GEOMETRY and stage 2 on DEPTH, `JOINT_FACTOR_MIN_M` = 8,192. Stage 2's
factored evaluation is what was losing shallow - -222% at m = 256, -19%
at 4,096 on the 10 Sep rig - and below 8,192 it no longer runs at all.

So the turnover those rounds found has already been gated out, and what
remains below 8,192 is stage 1's additive product plus the owned-buffer
stripe scheduler. The hypothesis this round exists to REFUTE is that the
remainder pays, or is neutral, at every depth the Forney gate admits.

Designed to be able to refute it:

  * the WHOLE-ARM A/B (`off` against `--fast`) is the only thing that can
    answer "may the default flip", because that is the comparison a user
    experiences. The stage marks cannot: `run_joint` fuses both stages
    per stripe and splits one wall by worker share, so a stage 2 that
    runs slower mechanically pushes stage 1's attributed share down at
    constant real cost. An attributed mark is not a control.
  * an `aa` arm at EVERY rung, byte-identical to `off`, so the noise
    floor is paired and per-depth rather than assumed. A signal smaller
    than its own rung's A/A is not a signal.
  * rungs bracketing BOTH gates - the Forney gate (704 on NEON, 1,280 on
    x86) below which `--fast` cannot engage at all and the two arms are
    the same code, and `JOINT_FACTOR_MIN_M` at 8,192 - plus the deepest
    rungs as a POSITIVE CONTROL. If 12,288 and 16,384 do not reproduce
    the known 9-40% win, the round is measuring something other than what
    it thinks and every other row is void.
  * both stage labels parsed off the `NZBFAST_REPAIR_TIMING` trace onto
    the leg line. Since 11 Sep the two stages name their arms
    INDEPENDENTLY and all four combinations are reachable, so a round
    that reads stage 1's label and credits both stages to it is reading
    an arm it did not run. A FALLBACK can never be read as a result.
  * every leg gated on SHA-256 of all members, never on rc.

FIXTURE, and why this shape. 32 members of 512 slices at 262,144 B is
the stage-2 round's own fixture (`JOINT_FACTOR_MIN_M`'s docstring), so
the two rounds compose; the recovery count is doubled to 16,384 so m can
reach the deepest rung. 4 GiB of payload and 4 GiB of parity, ~16 GiB on
the SSD with the working copy. The 11 Sep `mcross` round asked for 23 GiB
of payload at 100% parity and died on `No space left on device` 3m45s in,
having spent 70 s of create first - the deep end of the ladder does not
need a big set, it needs a big m, and m is capped by the BLOCK count.

THE n AXIS. `--members` and `--memslices` were module constants until
11 Sep 2026 and are now arguments, because section 4.5 of the crossover
write-up varied BLOCK SIZE by 4x and found the crossing unmoved but never
varied SET SHAPE - every fixture in it was 32x512, so n = 16,384 source
blocks throughout, and 4.5 records that in bold as a gap rather than a
result. Sweeping it is `--memslices 256 / 512 / 1024` at a fixed
`--members`, which holds the FILE count (and so the hashing parallelism
`-T` derives from it) while moving only the block count:

    jcross.py --slice 1048576 --memslices 256  --tag n8k    # 0.5x
    jcross.py --slice 1048576                  --tag n16k   # 1x, the shipped shape
    jcross.py --slice 1048576 --memslices 1024 --tag n32k   # 2x

Read those three for where the arm first clears its own per-rung A/A
floor, NOT for the size of the win: the win necessarily moves with `n`
for an uninteresting reason, because the solve is a smaller share of a
whole repair whose verify scan grows with the payload.

Usage:
    jcross.py                 # the full ladder
    jcross.py --rungs 704,16384 --reps 1 --arms off,fast    # calibration
"""
import os, re, sys, argparse, subprocess, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import (RigLock, utcnow, run_leg, sha256_file, gate, damage_picks,
                  apply_damage, restore_slices, remove_strays, warm,
                  box_facts, bin_facts, harness_facts, rig_vol_facts,
                  rig_stamp, set_quiet_budget)

HOME = os.path.expanduser("~")
BIN = os.path.join(HOME, "pubrun", "bin")
RIG_BASE = os.path.join(HOME, "pubrun", "jcross")
LOCK = os.path.join(HOME, "pubrun", "jcross.lock")

# BLOCK SIZE AND SET SHAPE ARE BOTH PARAMETERS, not constants, and the rig
# directory is keyed on both so no two fixtures ever share a directory.
#
# A threshold on `m` alone is only valid if the crossing does not move with
# the OTHER axes, and there are two of them. Block size was answered on
# 11 Sep 2026 - same box, same rungs, same arms, 4x the block size, the
# shape identical and the deep end agreeing to about a point
# (an internal note section 4.5). SET SHAPE
# was not, because every fixture in that round was 32 members of 512 slices
# and so carried n = 16,384 source blocks throughout; 4.5 recorded that in
# bold as a gap rather than a result, and this is the knob that closes it.
# The precedent one level down is `backsub_min_missing`, whose docstring
# reports an n-axis sweep over n = 5,600 / 11,200 / 22,400 finding m*
# unmoved at every n on two boxes.
#
# `--recovery` is separate from the shape ON PURPOSE, and defaults to a
# COUNT rather than a percentage. A sweep of `n` at constant redundancy
# would move the parity pool with the payload and so change two things at
# once; holding the recovery count fixed at the ladder's deepest rung keeps
# the par2 side byte-identical across the sweep, and the redundancy
# PERCENTAGE is then a derived quantity that the PROTOCOL line prints
# rather than a second independent variable.
SLICE = 262144
NMEM = 32
MEMSLICES = 512
SRCBLK = NMEM * MEMSLICES             # 16,384 source blocks at the default shape
RBLK = 16384                          # enough recovery for m up to the deepest rung


def membytes():
    return SLICE * MEMSLICES

# Rungs. The shallow end densely, because that is the half nobody has
# localised, and because the cost of being wrong there is what a common
# repair pays. 256 is BELOW the NEON Forney gate (704) and below the x86
# one (1,280), so both arms run identical code there: a free end-to-end
# A/A that travels with the round. 8,192 is JOINT_FACTOR_MIN_M itself.
# 12,288 and 16,384 are the positive control.
RUNGS = [256, 704, 1024, 1536, 2048, 3072, 4096, 5120,
         6144, 7168, 8192, 10240, 12288, 16384]

# THREE arms of ONE binary, and `aa` is `off` twice. The A/B cannot differ
# by anything except the switch, and the A/A cannot differ by anything at
# all - which is the point: it measures the rig, at the same depth, under
# the same load, in the same rep.
# Each arm is (extra argv, extra env). `aa` is `off` twice.
#
# The first three answer "may the DEFAULT flip": they move the whole switch,
# which is the comparison a user experiences.
#
# `s2off` / `s2on` answer the different question of where JOINT_FACTOR_MIN_M
# belongs on THIS class. Both hold stage 1 on the additive product
# (NZBFAST_FORNEY_JOINT=1 on both sides) and differ only in
# NZBFAST_FORNEY_FACTOR, so the only thing moving is the arm that constant
# gates. Forced in BOTH directions deliberately: an arm left on the default
# stops measuring the moment the default moves - which is precisely what this
# round may be about to do.
# `off` and `aa` name the shipped solve EXPLICITLY rather than relying on the
# binary's default. The default is exactly what this round may be about to
# move, and an arm left on a default stops measuring the moment it does - the
# same trap `NZBFAST_FORNEY_FACTOR` is forced in both directions to avoid.
# With the switch default-off this is a no-op; with it default-on it is the
# difference between an A/B and two copies of the same arm.
ARMS = {
    "off":   ([], {"NZBFAST_FORNEY_JOINT": "0"}),
    "fast":  (["--fast"], {}),
    "aa":    ([], {"NZBFAST_FORNEY_JOINT": "0"}),
    "s2off": ([], {"NZBFAST_FORNEY_JOINT": "1", "NZBFAST_FORNEY_FACTOR": "off"}),
    "s2on":  ([], {"NZBFAST_FORNEY_JOINT": "1", "NZBFAST_FORNEY_FACTOR": "on"}),
    # The A/A for the stage-2 pair, and it has to be a second copy of
    # `s2off` rather than `aa`. `aa` is the SHIPPED solve, so pairing
    # s2off against it measures stage 1 - an A/B wearing the name of a
    # floor, which would make every stage-2 row look noisier than the rig
    # is and could hide the crossing entirely.
    "s2aa":  ([], {"NZBFAST_FORNEY_JOINT": "1", "NZBFAST_FORNEY_FACTOR": "off"}),
    # The stage-1 trio, 12 Sep 2026, the twin of jcross.ps1's: both arms run
    # the joint scheduler with stage 2 on its own gate and differ only in
    # whether stage 1 takes the additive kernel or is HELD on the shipped
    # arithmetic (NZBFAST_FORNEY_STAGE1 in joint.rs), which prices the kernel
    # ALONE. The A/A is a second copy of `s1off`, for the reason `s2aa` gives.
    "s1off": ([], {"NZBFAST_FORNEY_JOINT": "1", "NZBFAST_FORNEY_STAGE1": "owned"}),
    "s1on":  ([], {"NZBFAST_FORNEY_JOINT": "1", "NZBFAST_FORNEY_STAGE1": "kernel"}),
    "s1aa":  ([], {"NZBFAST_FORNEY_JOINT": "1", "NZBFAST_FORNEY_STAGE1": "owned"}),
}
PARFAST = "parfast-jx"          # deployed beside `parfast-joint`, never over it:
                               # a round already in flight must not change
                               # binary underneath itself.
THREADS = min(32, os.cpu_count() or 8)


def tflag(files):
    """Files hashed in parallel: parfast's own default rule, min(cores, files).
    A flat -T16 caps a box with more cores than that - see mfull.py."""
    return min(os.cpu_count() or 1, max(1, files))


def rargv(extra, files):
    return ["r", "-q", "-t%d" % THREADS, "-T%d" % tflag(files)] + list(extra) + ["f.par2"]


STAGE_RE = re.compile(r"forney stage ([12]) \((.+?)\): \d")

# THE NEGATIVE CONTROL, and neither stage mark can be one.
#
# `par2repair.rs`'s `mark("verify targets + volume scan")` times the pass that
# reads and hashes every target file before the solver is entered. No arm of
# this round can reach it: it runs before the Forney gate is consulted, on
# every leg, at every rung - including the rungs below the gate where the
# solver is never entered at all.
#
# It is needed BECAUSE the stage marks look like controls and are not. Both are
# attributed SHARES of one fused wall (`split(s1)` / `split(s2)` in joint.rs),
# so a stage-1 mark that holds still across the arms says the attribution held
# still, not that the box did. A round on a disturbed box completes every leg,
# passes every SHA gate, and reads pure noise - see
# the banked discarded-leg logs for that signature. A
# phase the change cannot touch, flat across the reps, is what says those legs
# were on a quiet box.
#
# `{label}: +{:.2?} (total {:.2?})` is the emit format, so the unit travels
# with the number and has to be converted rather than assumed. Rust's Duration
# Debug emits exactly ns / us / ms / s; `us` and the ASCII spelling are both
# accepted because the micro sign is the one character in this trace that a
# console code page can mangle.
CTRL_RE = re.compile(
    r"verify targets \+ volume scan: \+([0-9.]+)(ns|µs|μs|us|ms|s) \(total"
)
CTRL_SCALE = {"ns": 1e-9, "µs": 1e-6, "μs": 1e-6, "us": 1e-6,
              "ms": 1e-3, "s": 1.0}


def stage_labels(errpath):
    """(stage1, stage2, raw1, raw2, ctrl_s) as the ENGINE named them.

    `ctrl_s` is the control phase in SECONDS, or `None` when the trace did not
    carry it - see `CTRL_RE`. It is returned from here rather than from a
    second reader because this function already has the file open, and a
    second pass over a multi-megabyte trace per leg is a cost the round pays
    126 times.

    ONE TOKEN PER STAGE, no spaces, with the engine's own wording carried
    beside it. An earlier version of this function returned the engine's raw
    clause and was wrong in three ways at once, all found by the lane porting
    this round to Windows on 11 Sep 2026:

      * it guarded stage 1 on `"forney stage 1 (joint" in line`, so the
        SHIPPED path - `forney stage 1 (hankel, nseg=..., dft=...)`, no
        "joint" anywhere - never matched and every `off`/`aa` leg reported
        `no-label`. That reads as "the trace is missing" rather than "the
        shipped arithmetic ran", on the arm the A/B compares AGAINST at
        every rung.
      * the raw clause contains spaces and commas, so printed unquoted into
        a `key=value` leg line it truncates at the first space for any
        reader that splits on whitespace. `jsum.py` survives it by scanning
        for the next ` key=`; nothing else does.
      * `rsplit(")")` and a substring collapse to the bare word `FALLBACK`
        both happened to work on the shapes this fleet ran, and neither is
        right: the joint lines end in "(attributed by worker share)", so the
        rsplit over-captures and is only rescued by the substring test after
        it - and that test threw the KERNEL NAME away, so a fallback on the
        short-tail arm and one on the whole/demand arm were indistinguishable.

    The regex anchors on the DURATION that follows the label, which is the
    one thing that cannot appear inside it, and is non-greedy to the first
    `): <digit>`. That survives "group(s)" and "tile(s)" by construction
    rather than by accident.
    """
    try:
        txt = open(errpath, errors="replace").read()
    except OSError:
        return "no-err", "no-err", "", "", None
    seen = {"1": [], "2": []}
    raw = {"1": "", "2": ""}
    ctrl = None
    for line in txt.splitlines():
        m = STAGE_RE.search(line)
        if not m:
            c = CTRL_RE.search(line)
            if c:
                ctrl = float(c.group(1)) * CTRL_SCALE[c.group(2)]
            continue
        stage, body = m.group(1), m.group(2)
        raw[stage] = body
        if stage == "1":
            if "joint" not in body:
                tok = "hankel" if body.startswith("hankel") else "unknown"
            elif "short tail" in body:
                tok = "joint-short-tail"
            elif "peeled" in body:
                tok = "joint-peeled"
            elif "whole/demand" in body:
                tok = "joint-whole-demand"
            else:
                tok = "joint-other"
        elif "joint factor" in body:
            tok = "joint-factor"
        elif "joint scheduler" in body:
            tok = "joint-FALLBACK"
        elif body.startswith("evaluate"):
            tok = "evaluate"
        else:
            tok = "unknown"
        # A FALLBACK keeps the arm it fell back FROM: that is the whole
        # point of naming the kernel, and the bare word discards it.
        if "FALLBACK" in body and not tok.endswith("FALLBACK"):
            tok += "-FALLBACK"
        if tok not in seen[stage]:
            seen[stage].append(tok)
    # Several distinct labels in one leg JOIN rather than the last one
    # silently winning - a stripe scheduler may legitimately take more than
    # one arm across a repair, and a round must be able to see that.
    s1 = "+".join(seen["1"]) or "no-label"
    s2 = "+".join(seen["2"]) or "no-label"
    return s1, s2, raw["1"], raw["2"], ctrl


def build_fixture(pristine, work, logs, members):
    for d in (pristine, work, logs):
        os.makedirs(d, exist_ok=True)
    for nm in members:
        p = os.path.join(pristine, nm)
        if os.path.exists(p) and os.path.getsize(p) == membytes():
            continue
        subprocess.check_call(["dd", "if=/dev/urandom", "of=" + p,
                               "bs=1048576", "count=%d" % (membytes() >> 20)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gold = {nm: sha256_file(os.path.join(pristine, nm)) for nm in members}
    print("FIXTURE members=%d distinct_member_sha=%d/%d bytes=%d source_blocks=%d"
          % (len(members), len(set(gold.values())), len(members),
             sum(os.path.getsize(os.path.join(pristine, m)) for m in members),
             SRCBLK), flush=True)
    if len(set(gold.values())) != len(members):
        print("JCROSS-FAIL payload members not distinct", flush=True)
        sys.exit(9)
    # The near-copy defect that voided the September publication rounds was
    # detected by hashing the SAME slice index in every member. Do that.
    probe = set()
    for nm in members:
        with open(os.path.join(pristine, nm), "rb") as f:
            f.seek(5 * SLICE)
            probe.add(hashlib.sha256(f.read(SLICE)).hexdigest())
    print("SLICE-PROBE index=5 unique=%d/%d" % (len(probe), len(members)), flush=True)
    if len(probe) != len(members):
        print("JCROSS-FAIL payload is near-copies", flush=True)
        sys.exit(9)
    for nm in members:
        print("GOLD %s %s" % (nm, gold[nm]), flush=True)
    return gold


def main():
    global SLICE, NMEM, MEMSLICES, SRCBLK, RBLK, PARFAST
    ap = argparse.ArgumentParser()
    ap.add_argument("--rungs", default=",".join(str(r) for r in RUNGS))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--arms", default="off,fast,aa")
    ap.add_argument("--tag", default="jcross")
    ap.add_argument("--slice", type=int, default=SLICE,
                    help="block size in bytes; the fixture directory is keyed on it")
    ap.add_argument("--members", type=int, default=NMEM,
                    help="files in the set; the fixture directory is keyed on it")
    ap.add_argument("--memslices", type=int, default=MEMSLICES,
                    help="blocks per member; members*memslices is n, the source "
                         "block count, which is the axis section 4.5 left open")
    ap.add_argument("--recovery", type=int, default=RBLK,
                    help="recovery block count, held CONSTANT across an n sweep "
                         "so the parity pool is not a second variable")
    # THE RIG CAN LIVE OFF THE BOOT VOLUME, and on a long high-churn round it
    # sometimes MUST. A repair leg rewrites its damaged blocks and restores
    # them, so an n-deep ladder churns tens of GiB per rep - and on a volume
    # inside the Time Machine backup set every hourly local snapshot PINS the
    # blocks that churn replaced. Measured on apple-m3-ultra, 11 Sep 2026: a 1 MiB
    # n = 16,384 round started with 159.7 GB free, spent 69 GB of that on its
    # own fixture and a further ~59 GB on snapshot-pinned churn, and finished
    # its last reps at 1.7% free. Deleting the previous round's 48 GiB fixture
    # returned ZERO, because the snapshots pinned that too.
    #
    # That is not a slow box, it is a measurement of the volume: the read-only
    # `verify targets + volume scan` phase held FLAT at 0.97 s (+0.2%) across
    # all five reps while the median leg wall went 12.71 s -> 25.42 s, so CPU
    # and read throughput were fine and the write side was not. An Apple SSD
    # carves its SLC cache out of FREE SPACE (.claude/MACHINES.md), so a round
    # that fills its own volume degrades itself, progressively, in a way that
    # pairing cancels only partly - the A/A floors at the deep rungs blew out
    # to 8-29% where the same rungs on the roomy run read 4-11%.
    #
    # So: point the rig at a volume with headroom that is EXCLUDED from Time
    # Machine (`tmutil isexcluded <path>`, and `tmutil listlocalsnapshots
    # <path>` should list none). Check both before trusting a long round, and
    # keep every column of a sweep on ONE volume - moving the rig between
    # columns makes the device a second variable and answers nothing.
    # See `pdrv.set_quiet_budget`. An n sweep's deepest column is a two-hour
    # ladder and an aborted round loses its partial, so it should outlast a
    # contacts-sync storm rather than be killed by one.
    ap.add_argument("--quiet-tries", type=int, default=10,
                    help="load-guard retries before a round aborts (x --quiet-wait)")
    ap.add_argument("--quiet-wait", type=int, default=30,
                    help="seconds between load-guard retries")
    # The binary the arms run, deployed BESIDE `parfast-jx` under its own
    # name, so a candidate build never overwrites the one a round in flight
    # is measuring. The twin of jcross.ps1's -Exe (12 Sep 2026).
    ap.add_argument("--exe", default=PARFAST,
                    help="binary name under ~/pubrun/bin (default parfast-jx)")
    ap.add_argument("--rig-base", default=RIG_BASE,
                    help="path prefix for the fixture directory; the slice and "
                         "shape are appended. Use a roomy TM-excluded volume "
                         "for long high-churn rounds - see the note at this flag")
    a = ap.parse_args()
    SLICE = a.slice
    NMEM = a.members
    MEMSLICES = a.memslices
    SRCBLK = NMEM * MEMSLICES
    RBLK = a.recovery
    PARFAST = a.exe
    # `.noindex` covers the FILE indexer, and that is all it is claimed to
    # do here. Spotlight skips any directory whose NAME ends in `.noindex`,
    # where `.metadata_never_index` is advisory; every leg rewrites the
    # damaged slices, so a fixture inside an indexed tree is re-indexed for
    # a whole round rather than once. Cheap, correct, worth having.
    #
    # **It is NOT the fix for the aborts of 11 Sep 2026, and an earlier
    # version of this comment said it was.** Four rounds died that day -
    # apple-m1-ultra-128gb twice (209% and 212% of a 200% ceiling) and the M5 Max
    # twice (194% and 268% of 180%) - and the daemon named in every one is
    # `corespotlightd`, which indexes app and content items and is not the
    # file indexer (`mds`/`mdworker` is). Two pieces of the evidence say so
    # directly: the same pid was responsible across a full fixture rebuild,
    # and the M5 aborted AGAIN with this suffix already in place. A
    # per-directory marker of either kind was aimed at something that was
    # not doing the work.
    #
    # So do not spend a round on the theory that a marker rescues those two
    # boxes. They are the box's own workload, and the durable answers are a
    # longer wait than the guard's 10x30 s or treating apple-m1-ultra-128gb and the M5 as
    # unreliable for timed work - which, with two lanes having now lost
    # rounds on both, is the more likely reading.
    # KEYED ON THE SHAPE AS WELL AS THE SIZE, but only when the shape is not
    # the default one. Every fixture built before 11 Sep 2026 is 32x512 and
    # lives at `jcross-<slice>.noindex`; appending the shape unconditionally
    # would orphan all of them and make every box rebuild a set it already
    # has, which on the 2x rung is 48 GiB of create nobody asked for. The
    # default shape therefore keeps its historical path exactly, and only a
    # NEW shape gets a new directory - which is the property that matters,
    # since the failure this key exists to prevent is two shapes sharing one
    # fixture, not a path that looks tidy.
    shape = "" if (NMEM, MEMSLICES) == (32, 512) else "-%dx%d" % (NMEM, MEMSLICES)
    RIG = "%s-%d%s.noindex" % (a.rig_base, SLICE, shape)
    rungs = [int(x) for x in a.rungs.split(",") if x]
    arms = [x for x in a.arms.split(",") if x]
    for nm in arms:
        if nm not in ARMS:
            sys.exit("unknown arm %r" % nm)
    if max(rungs) > SRCBLK:
        sys.exit("rung %d exceeds %d source blocks (members=%d x memslices=%d)"
                 % (max(rungs), SRCBLK, NMEM, MEMSLICES))
    # AND m cannot exceed the recovery count either, which is a NEW way to be
    # wrong now that the parity pool is held constant while `n` moves: at the
    # 2x rung of an n sweep the set is no longer at 100% redundancy, so
    # `rung <= SRCBLK` stops being the binding constraint and a ladder that
    # only checked it would ask for a repair the set cannot serve. Refuse at
    # the top rather than discovering it on the deepest leg, an hour in.
    if max(rungs) > RBLK:
        sys.exit("rung %d exceeds %d recovery blocks - raise --recovery or "
                 "lower the deepest rung" % (max(rungs), RBLK))

    set_quiet_budget(a.quiet_tries, a.quiet_wait)
    lock = RigLock(LOCK)
    lock.take()
    try:
        print("JCROSS-START %s tag=%s" % (utcnow(), a.tag), flush=True)
        box_facts()
        bin_facts([os.path.join(BIN, PARFAST)])
        # The DRIVER's provenance, not just the binary's - see
        # `pdrv.harness_facts`. A round on a parfast rig has no other drift
        # evidence: `tools/bench-deploy-check.py` refuses every box this
        # harness runs on.
        harness_facts([os.path.abspath(__file__),
                       os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "pdrv.py")])
        # REDUNDANCY IS DERIVED AND PRINTED, never asserted. It was the literal
        # `redundancy_pct=100.0` until the n axis opened on 11 Sep 2026, which
        # was true of every fixture that existed then and becomes a lie the
        # moment the recovery count is held while `n` moves - 200% at the 0.5x
        # rung and 50% at the 2x rung of the sweep this line now has to
        # describe. A protocol line that states a constant it does not measure
        # is the shape of every rubber-stamp in this campaign's history.
        rig_vol_facts(RIG)
        print("PROTOCOL slice=%d members=%d memslices=%d recovery_blocks=%d "
              "source_blocks=%d redundancy_pct=%.1f "
              "damage=scattered-seeded-slice-overwrite "
              "reps=%d arms=%s gate=sha256-all-members prewarm=full-read-of-work-dir "
              "arm_order=alternating-by-rep"
              % (SLICE, NMEM, MEMSLICES, RBLK, SRCBLK,
                 RBLK * 100.0 / SRCBLK, a.reps, "/".join(arms)), flush=True)
        for nm in arms:
            print("ARGV %s repair='%s' env=%s"
                  % (nm, " ".join(rargv(ARMS[nm][0], NMEM)),
                     ",".join("%s=%s" % kv for kv in sorted(ARMS[nm][1].items())) or "-"), flush=True)

        pristine = os.path.join(RIG, "pristine")
        work = os.path.join(RIG, "work")
        logs = os.path.join(RIG, "logs")
        members = ["p%02d.bin" % i for i in range(NMEM)]
        gold = build_fixture(pristine, work, logs, members)

        parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
        if not parfiles:
            r = run_leg(os.path.join(BIN, PARFAST),
                        ["c", "-q", "-t%d" % THREADS, "-T%d" % tflag(len(members)),
                         "-s%d" % SLICE, "-c%d" % RBLK, "f.par2"] + members,
                        pristine, os.path.join(logs, "create"))
            parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
            parbytes = sum(os.path.getsize(os.path.join(pristine, f)) for f in parfiles)
            print("CREATE tool=parfast rc=%d wall=%s cpu=%s peak_mb=%s par2files=%d "
                  "par2bytes=%d errlen=%d"
                  % (r["rc"], r["wall"], r["cpu"], r["peak_mb"], len(parfiles),
                     parbytes, r["errlen"]), flush=True)
            if r["rc"] != 0 or not parfiles:
                print("JCROSS-FAIL create rc=%d" % r["rc"], flush=True)
                sys.exit(9)
        else:
            print("CREATE reused par2files=%d" % len(parfiles), flush=True)

        keep = set(members) | set(parfiles)
        for nm in keep:
            src, dst = os.path.join(pristine, nm), os.path.join(work, nm)
            if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
                subprocess.check_call(["cp", src, dst])
        remove_strays(work, keep)
        good, bad = gate(work, members, gold)
        if good != len(members):
            for nm in bad:
                subprocess.check_call(["cp", os.path.join(pristine, nm),
                                       os.path.join(work, nm)])

        def run_rung(armname, rung, rep, seed, tag):
            argv = rargv(ARMS[armname][0], len(members))
            warm(work)
            picks = damage_picks(work, members, SLICE, rung, seed)
            wrote = apply_damage(work, members, SLICE, picks, seed)
            pre_good, _ = gate(work, members, gold)
            legenv = {"NZBFAST_REPAIR_TIMING": "1"}
            legenv.update(ARMS[armname][1])
            res = run_leg(os.path.join(BIN, PARFAST), argv, work,
                          os.path.join(logs, tag), env_extra=legenv)
            post_good, post_bad = gate(work, members, gold)
            strays = remove_strays(work, keep)
            s1, s2, r1, r2, ctrl = stage_labels(os.path.join(logs, tag) + ".err")
            print("LEG round=%s rep=%d m=%d arm=%s wall=%s cpu=%s cpu_over_wall=%s "
                  "peak_mb=%s rc=%d restored=%d/%d damaged_members=%d "
                  "blocks_written=%d strays=%d seed=%d stage1=%s stage2=%s "
                  "stage1_raw='%s' stage2_raw='%s' ctrl_s=%s "
                  "foreign_cpu=%s foreign_after=%s steal_pct=%s "
                  "errlen=%d ts=%s rig=%s"
                  % (a.tag, rep, rung, armname, res["wall"], res["cpu"],
                     round(res["cpu"] / max(res["wall"], 0.001), 2),
                     res["peak_mb"], res["rc"], post_good, len(members),
                     len(members) - pre_good, wrote, strays, seed, s1, s2,
                     r1, r2,
                     "n/a" if ctrl is None else "%.6f" % ctrl,
                     res.get("foreign_cpu"), res.get("foreign_after"),
                     res.get("steal_pct"), res["errlen"], utcnow(),
                     rig_stamp()), flush=True)
            restore_slices(work, pristine, members, SLICE, picks)
            g2, b2 = gate(work, members, gold)
            if g2 != len(members):
                for nm in b2:
                    subprocess.check_call(["cp", os.path.join(pristine, nm),
                                           os.path.join(work, nm)])
                g3, _ = gate(work, members, gold)
                print("RESET rep=%d m=%d arm=%s after_full_copy=%d/%d"
                      % (rep, rung, armname, g3, len(members)), flush=True)
                if g3 != len(members):
                    print("JCROSS-FAIL work dir unrecoverable", flush=True)
                    sys.exit(9)
            for nm in parfiles:
                subprocess.check_call(["cp", os.path.join(pristine, nm),
                                       os.path.join(work, nm)])

        # Untimed and discarded. Rep 1 runs systematically slow where the set
        # is not yet in page cache, and a median of an even count is a mean,
        # so it cannot throw a cold reading away.
        print("WARMUP-START %s" % utcnow(), flush=True)
        for armname in arms:
            run_rung(armname, 64, 0, 20260911, "warm-%s" % armname)
        print("WARMUP-END %s" % utcnow(), flush=True)

        for rep in range(1, a.reps + 1):
            # Arm ORDER ROTATES by rep. Within a rung the first arm pays any
            # residual cache and thermal cost of the damage write that precedes
            # it, and the first arm of the FIRST rung additionally pays the cost
            # of whatever the previous rep left dirty - so holding one arm in
            # one position folds that into the signal in the same direction at
            # every depth.
            #
            # **THIS WAS `reversed()` UNTIL 12 SEP 2026, AND REVERSING THREE
            # ARMS IS NOT ALTERNATING THEM.** `[off, fast, aa]` reversed is
            # `[aa, fast, off]`: the middle element does not move, so across
            # every rep of every round this harness has ever run, `fast` - the
            # arm under test - was NEVER first and never last, while `off` and
            # `aa` split those slots between them. Any position-dependent cost
            # was therefore paid by the baseline and the floor and never by the
            # arm the table reports.
            #
            # Caught on the n-axis sweep, at the one rung where the cost is
            # comparable to the leg. m = 256 is the first rung of each rep and
            # its first leg ran 8.6 s against 4.46 s for the other two, in all
            # five reps, landing on `off` in reps 1/3/5 and `aa` in reps 2/4:
            #
            #     rep1  off 7.774  fast 4.451  aa 4.430
            #     rep2  off 4.476  fast 4.464  aa 8.682
            #     rep3  off 8.608  fast 4.464  aa 4.458
            #     rep4  off 4.486  fast 4.473  aa 8.609
            #     rep5  off 8.642  fast 4.460  aa 4.469
            #
            # That row reported +42.75% for an arm that CANNOT engage below the
            # Forney gate of 704 and was running identical code. The A/A floor
            # caught it - 93.97%, so `jsum` marked the row a wash and nothing
            # was published - which is the floor doing exactly its job, and is
            # also the only reason a systematic this old stayed invisible: at
            # every deeper rung the effect is far below the floor, where it
            # BIASES a median instead of announcing itself.
            #
            # A rotation puts every arm in every position. Prefer a rep count
            # that is a MULTIPLE of the arm count, or the balance is only
            # approximate: at 3 arms and 5 reps the first slot goes 2/2/1.
            k = (rep - 1) % len(arms)
            order = arms[k:] + arms[:k]
            for rung in rungs:
                seed = 20260911 + rung * 7 + rep   # identical damage for all arms
                for armname in order:
                    run_rung(armname, rung, rep, seed,
                             "r%d-m%d-%s" % (rep, rung, armname))
            print("JCROSS-REP-END rep=%d %s" % (rep, utcnow()), flush=True)
        print("JCROSS-END %s" % utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
