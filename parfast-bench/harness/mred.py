#!/usr/bin/env python3
"""mred.py - the THREE-RUN repeat of the high-redundancy create cells.

mred.py established the SHAPE at 25% and 30% redundancy with ONE run per
cell, which was the right call for a shape and is the wrong basis for a
published digit. Three of those ten cells say so out loud: parfast reads 8.98 s at 30 GiB/25%
and 13.03 s at 30 GiB/30%, 20.54 s at 50/25 against 19.75 s at 50/30, and
45.50 s at 80/25 against 36.33 s at 80/30 - cells that are SLOWER at LESS
redundancy than at more.

THE BANKED CPU COLUMN ALREADY NAMES WHICH READING IS WRONG, and it is worth
knowing before this round starts rather than after. More redundancy is strictly
more arithmetic, so CPU seconds must rise with it, and in mturn's own log they
do at every one of the five parfast cells: +3.2, +1.4, +9.6, +2.1, +2.7 per
cent. Only the WALL misbehaves. Parallel efficiency says the same thing in one
number - parfast falls from 25.8 of 32 cores at 30 GiB/25% to 19.5 at 30/30,
and reads 15.1 at the anomalously slow 80/25 against 19.4 at 80/30. Turbo, over
the same ten cells, tracks its own CPU to within 0.6 points everywhere and sits
pinned at 30.0-30.3 of 32 cores.

So this is not symmetric noise in a clean instrument. parfast's create at large
sets finishes fast enough to leave the arithmetic behind - peak working set is
84.8 GB at 80 GiB - and what is left is bound by something else, which is
exactly the regime where a wall varies and a CPU count does not. The published
column is the WALL, because that is what a user waits for, so the fix is
repetition and a stated spread rather than a switch to CPU seconds.

So this round re-runs exactly the ten n=1 cells, three times each, interleaved
by rep rather than three times in a row, and nothing else. The n=3 cells of the
sweep (every 20% row) are already repeated and are not touched.

SAME BOX AS THE SWEEP, DELIBERATELY. Every 20% row in the published table was
measured on this machine; a repeat of the 25/30 rows on a different one would
produce a table whose rows are not comparable to each other, which is worse
than a table with a stated n=1.

Cost, projected from mred's own walls: turbo sums to ~4,400 s a rep and
parfast to ~160 s, so ~75 minutes a rep and ~4 hours for the three, plus the
80 GiB payload build if it is not already there.
"""

import os, subprocess, sys, time, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import (RigLock, utcnow, run_leg, box_facts, bin_facts,
                  harness_facts, rig_stamp)

# FILE-HASH PARALLELISM IS PER-ROUND, NOT A CONSTANT.
#
# Every round here used to pass a flat `-T16`. `-T` is files hashed in parallel,
# so on a fixture with MORE files than 16, on a box with more than 16 cores,
# that CAPPED par2cmdline-turbo below what it could use - 16 of a possible 32 on
# the M3 Ultra - while parfast was unaffected, because parfast's own default is
# already min(cpu_workers, files) and it ignores the switch.
#
# That hobbles the competitor and INFLATES our ratio, which is the dangerous
# direction. So -T is now computed per round as min(cores, files): parfast's own
# default rule, and turbo's best. Both tools get the same rule rather than the
# same literal.
def tflag(files):
    return min(os.cpu_count() or 1, max(1, files))

HOME = os.path.expanduser("~")
BIN = os.path.join(HOME, "pubrun", "bin")
RIG = os.path.join(HOME, "pubrun", "red")
LOCK = os.path.join(HOME, "pubrun", "red.lock")
WAIT_LOG = os.path.join(HOME, "pubrun", "shape.log")
WAIT_MARK = None   # unused: see the note in main()
PAY = os.path.join(HOME, "pubrun", "swp", "pay")
# No SIZES/RED/REPS here: mturn's low-redundancy pass is deliberately absent
# from this round, and leaving its constants behind would read as if it still
# ran. The high-redundancy constants below are the whole round.

# High-redundancy pass, added 10 Sep after establishing that PROTECTION FALLS
# WITH FILE SIZE at constant redundancy. PAR2 caps a set at 32,768 slices, so
# past ~23 GiB the block grows while the block count is pinned; a lost article
# smaller than a block still costs the whole block, so a nominal 20% delivers
# only 5.9% article-loss tolerance at 80 GiB. The settings below are therefore
# not exotic, they are what a poster of a large set has to reach for - which is
# also why measuring them is not cherry-picking a flattering regime.
#
# THREE reps, and the loop below is re-ordered so they INTERLEAVE: rep 1 of
# every cell, then rep 2, then rep 3. Three runs of a cell back to back share
# whatever the box was doing for those four minutes, which is exactly the thing
# repetition is supposed to average out.
HI_SIZES = [10, 23, 30, 50, 80]
HI_REDS = [25, 30]
HI_REPS = (1, 2, 3)
THREADS = 32
GIB = 1 << 30
BASE_SLICE = 768000
SLICE_CAP = 32768


def slice_for(g):
    if g * -(-GIB // BASE_SLICE) <= SLICE_CAP:
        return BASE_SLICE
    per = SLICE_CAP // g
    return ((-(-GIB // per)) + 3) // 4 * 4


def main():
    # marker wait removed 11 Sep 2026 - see mfull.py. A banked log
    # is a renamed log, and a round waiting on its marker then waits
    # forever with an empty log, looking alive. The rig lock serialises.
    time.sleep(60)

    lock = RigLock(LOCK)
    lock.take()
    try:
        print("MRED-START %s" % utcnow(), flush=True)
        box_facts()
        parfast = os.path.join(BIN, "parfast")
        turbo = os.path.join(BIN, "par2turbo")
        bin_facts([parfast, turbo])
        # The DRIVER's provenance, not just the binary's, and the per-leg `rig=`
        # token's round-start twin - see `pdrv.harness_facts`. A parfast round
        # has no other evidence of a harness that changed under it mid-round.
        harness_facts()
        print("PROTOCOL sizes_gib=%s redundancy_pct=%s reps=%d threads=%d "
              "recovery=in-place slice_cap=%d rep_order=interleaved "
              "gate=recovery-size-and-shape-never-rc"
              % (HI_SIZES, HI_REDS, len(HI_REPS), THREADS, SLICE_CAP), flush=True)
        src = os.path.join(RIG, "s")
        logs = os.path.join(RIG, "logs")
        os.makedirs(logs, exist_ok=True)
        # BUILD THE PAYLOAD IF IT IS NOT THERE. mturn.py simply borrowed
        # `swp/pay` and would have died on a box where the sweep had finished
        # and cleaned up after itself - which is every box, eventually. Same
        # generator and the same directory as the sweep, so where the sweep's
        # payload IS still present these members are the identical bytes and
        # the two rounds share a fixture lineage.
        os.makedirs(PAY, exist_ok=True)
        for i in range(max(HI_SIZES)):
            q = os.path.join(PAY, "p%02d.bin" % i)
            if not os.path.exists(q) or os.path.getsize(q) != GIB:
                subprocess.check_call(["dd", "if=/dev/urandom", "of=" + q,
                                       "bs=1048576", "count=1024"],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        print("PAYLOAD-READY members=%d bytes=%d"
              % (max(HI_SIZES), sum(os.path.getsize(os.path.join(PAY, f))
                                    for f in os.listdir(PAY))), flush=True)
        # The near-copy defect that voided the September rounds is caught by
        # hashing the SAME slice index in every member, never by hashing
        # members. A create round cannot repair its way out of near-copies, but
        # it CAN produce a recovery set whose size gate passes over degenerate
        # input, so the probe belongs here too.
        probe = set()
        for i in range(max(HI_SIZES)):
            with open(os.path.join(PAY, "p%02d.bin" % i), "rb") as f:
                f.seek(5 * BASE_SLICE)
                probe.add(hashlib.sha256(f.read(BASE_SLICE)).hexdigest())
        print("SLICE-PROBE index=5 unique=%d/%d" % (len(probe), max(HI_SIZES)), flush=True)
        if len(probe) != max(HI_SIZES):
            print("MRED-FAIL payload is near-copies", flush=True)
            sys.exit(9)
        arms = {"parfast": parfast, "turbo": turbo}
        # ONLY the high-redundancy cells, and the reps INTERLEAVE. mturn's
        # low-redundancy pass is not repeated here: every 20% row in the
        # published table already carries n=3 and re-measuring it would only
        # add a second, differently-timed copy of a settled number.
        #
        # rep is the OUTER loop deliberately. Three runs of one cell back to
        # back share whatever the box was doing for those four minutes, and
        # that is precisely the thing repetition exists to average out.
        for rep in HI_REPS:
            for g in HI_SIZES:
                bs = slice_for(g)
                blocks = g * -(-GIB // bs)
                subprocess.call(["rm", "-rf", src])
                os.makedirs(src, exist_ok=True)
                members = []
                for i in range(g):
                    nm = "p%02d.bin" % i
                    # hardlink the sweep's payload: same bytes, no second copy
                    os.link(os.path.join(PAY, nm), os.path.join(src, nm))
                    members.append(nm)
                for r in HI_REDS:
                    for arm in ("parfast", "turbo"):
                        for f in os.listdir(src):
                            if f.startswith("pub") and f.endswith(".par2"):
                                os.unlink(os.path.join(src, f))
                        res = run_leg(arms[arm],
                                      ["c", "-q", "-t%d" % THREADS, "-T%d" % tflag(len(members)),
                                       "-s%d" % bs, "-r%d" % r, "pub.par2"] + members,
                                      src, os.path.join(logs, "hi-%d-%d-r%d-%s" % (g, r, rep, arm)))
                        pf = sorted(f for f in os.listdir(src)
                                    if f.startswith("pub") and f.endswith(".par2"))
                        mb = sum(os.path.getsize(os.path.join(src, f)) for f in pf) / (1 << 20)
                        # foreign_cpu TRAVELS WITH THE NUMBER, and mturn.py's
                        # lines did not carry it, which is why its two
                        # contradicting cells could not be diagnosed from the
                        # log. The crossover lane measured this box at a
                        # foreign_cpu median of 25.8% and a p90 of 133.5% over
                        # a 135-leg round, so the load here is real and spiky
                        # and a single unpaired create can absorb it silently.
                        print("HIRED size=%d red=%d bs=%d blocks=%d rep=%d arm=%s wall=%s "
                              "cpu=%s cpu_over_wall=%s peak_mb=%s recovery_mb=%d files=%d "
                              "rc=%d foreign_cpu=%s errlen=%d ts=%s rig=%s"
                              % (g, r, bs, blocks, rep, arm, res["wall"], res["cpu"],
                                 round(res["cpu"] / max(res["wall"], 0.001), 2),
                                 res["peak_mb"], round(mb), len(pf), res["rc"],
                                 res.get("foreign_cpu"), res["errlen"], utcnow(),
                                 rig_stamp()), flush=True)
                        # The recovery set is gated on SIZE and SHAPE, not on rc:
                        # both tools have exited 0 over a refusal before.
                        lo, hi = g * 1024 * r / 100 * 0.90, g * 1024 * r / 100 * 1.25
                        if not (res["rc"] == 0 and len(pf) > 1 and lo <= mb <= hi):
                            print("GATE-FAIL hired size=%d red=%d rep=%d arm=%s rc=%d recovery_mb=%d"
                                  % (g, r, rep, arm, res["rc"], round(mb)), flush=True)
                for f in os.listdir(src):
                    if f.startswith("pub") and f.endswith(".par2"):
                        os.unlink(os.path.join(src, f))
                subprocess.call(["rm", "-rf", src])
                print("HIRED-SIZE-DONE size=%d rep=%d %s" % (g, rep, utcnow()), flush=True)
            print("MRED-REP-END rep=%d %s" % (rep, utcnow()), flush=True)

        print("MRED-END %s" % utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
