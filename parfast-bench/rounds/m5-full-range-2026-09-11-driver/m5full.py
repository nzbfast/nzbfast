#!/usr/bin/env python3
"""mfull.py - the FULL-RANGE repair ladder: verify, then one lost block, all the
way to a total loss.

The 15% ladder measures a realistic release redundancy, but 15% parity caps the
deepest possible repair at 2,098 of 13,990 blocks, which is a narrow window. This
round is 100% parity over 32,177 source blocks, so m runs from 1 to 32,177 - the
whole dynamic range PAR2 can express, four and a half orders of magnitude, ending
at every single source block reconstructed.

Originally the Apple 15% ladder; the fixture shape and rungs are the only change.

Same payload shape, same slice size, same recovery block count, same rung set
and the same seeded scattered damage as the i5 round, so the two architectures
compare leg for leg. Three extra rungs (640, 704, 896) bracket the NEON Forney
gate, which the 10 Sep recalibration moved from 896 to 704.

Payload is ten INDEPENDENT urandom members. The i5 round it pairs with replaced
a payload of ten near-copies where 1,398 of each member's 1,399 slices were
byte-identical across members, so both tools adopted blocks rather than
reconstructing them.
"""
import os, sys, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import (RigLock, utcnow, run_leg, sha256_file, gate, damage_picks,
                  apply_damage, restore_slices, remove_strays, warm,
                  box_facts, bin_facts, harness_facts)

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
RIG = os.path.join(HOME, "pubrun", "full")
LOCK = os.path.join(HOME, "pubrun", "full.lock")
SLICE = 768000
RBLK = 32177          # 100% parity: the deepest repair PAR2 can express
NMEM = 23
MEMBYTES = 1 << 30
RUNGS = [1, 4, 16, 64, 256, 1024, 2048, 4096, 8192, 16384, 24576, 32177]
REPS = [1, 2]
THREADS = 18
TOOLS = ["parfast", "par2turbo"]
# argv is a FUNCTION of the fixture, not a constant: -T must be
# min(cores, files) and the file count is not known until main() reads the
# payload. Building these at module level is what made the flat -T16 look
# harmless for so long.
def RARGV(tool, files):
    return ["r", "-q", "-t%d" % THREADS, "-T%d" % tflag(files), "f.par2"]


def VARGV(tool, files):
    return ["v", "-q", "-t%d" % THREADS, "-T%d" % tflag(files), "f.par2"]


def main():
    # nothing else is queued on this box, so no end marker to wait on; the
    # rig lock below is still what guarantees one timing round at a time.
    lock = RigLock(LOCK)
    lock.take()
    try:
        print("M5FULL-START %s" % utcnow(), flush=True)
        harness_facts()
        box_facts()
        bin_facts([os.path.join(BIN, t) for t in TOOLS])
        print("PROTOCOL slice=%d recovery_blocks=%d source_blocks=32177 "
              "redundancy_pct=100.0 damage=scattered-seeded-slice-overwrite "
              "reps=2 gate=sha256-all-members prewarm=full-read-of-work-dir"
              % (SLICE, RBLK), flush=True)
        for t in TOOLS:
            print("ARGV %s repair='%s' verify='%s'"
                  % (t, " ".join(RARGV(t, NMEM)), " ".join(VARGV(t, NMEM))), flush=True)

        pristine = os.path.join(RIG, "pristine")
        work = os.path.join(RIG, "work")
        logs = os.path.join(RIG, "logs")
        for d in (pristine, work, logs):
            os.makedirs(d, exist_ok=True)

        members = ["p%02d.bin" % i for i in range(NMEM)]
        for nm in members:
            p = os.path.join(pristine, nm)
            if os.path.exists(p) and os.path.getsize(p) == MEMBYTES:
                continue
            subprocess.check_call(["dd", "if=/dev/urandom", "of=" + p,
                                   "bs=1048576", "count=1024"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        gold = {nm: sha256_file(os.path.join(pristine, nm)) for nm in members}
        print("FIXTURE members=%d distinct_member_sha=%d/%d bytes=%d"
              % (len(members), len(set(gold.values())), len(members),
                 sum(os.path.getsize(os.path.join(pristine, m)) for m in members)),
              flush=True)
        if len(set(gold.values())) != len(members):
            print("M5FULL-FAIL payload members not distinct", flush=True)
            sys.exit(9)
        # prove the members are distinct the same way the defect was detected:
        # the SAME slice index, hashed in every member, must give NMEM hashes
        import hashlib
        probe = set()
        for nm in members:
            with open(os.path.join(pristine, nm), "rb") as f:
                f.seek(5 * SLICE)
                probe.add(hashlib.sha256(f.read(SLICE)).hexdigest())
        print("SLICE-PROBE index=5 unique=%d/%d" % (len(probe), len(members)), flush=True)
        if len(probe) != len(members):
            print("M5FULL-FAIL payload is near-copies", flush=True)
            sys.exit(9)
        for nm in members:
            print("GOLD %s %s" % (nm, gold[nm]), flush=True)

        for f in os.listdir(pristine):
            if f.endswith(".par2"):
                os.unlink(os.path.join(pristine, f))
        r = run_leg(os.path.join(BIN, "parfast"),
                    ["c", "-q", "-t18", "-T%d" % tflag(len(members)), "-s%d" % SLICE, "-c%d" % RBLK,
                     "f.par2"] + members,
                    pristine, os.path.join(logs, "create-parfast"))
        parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
        parbytes = sum(os.path.getsize(os.path.join(pristine, f)) for f in parfiles)
        print("CREATE tool=parfast rc=%d wall=%s cpu=%s peak_mb=%s par2files=%d "
              "par2bytes=%d errlen=%d"
              % (r["rc"], r["wall"], r["cpu"], r["peak_mb"], len(parfiles),
                 parbytes, r["errlen"]), flush=True)
        if r["rc"] != 0 or not parfiles:
            print("M5FULL-FAIL create rc=%d" % r["rc"], flush=True)
            sys.exit(9)

        keep = set(members) | set(parfiles)
        for nm in keep:
            src = os.path.join(pristine, nm)
            dst = os.path.join(work, nm)
            if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
                subprocess.check_call(["cp", src, dst])
        remove_strays(work, keep)
        good, bad = gate(work, members, gold)
        if good != len(members):
            for nm in bad:
                subprocess.check_call(["cp", os.path.join(pristine, nm),
                                       os.path.join(work, nm)])

        def run_rung(tool, rung, rep, seed, tag, argv):
            warm(work)
            picks = damage_picks(work, members, SLICE, rung, seed)
            wrote = apply_damage(work, members, SLICE, picks, seed)
            pre_good, _ = gate(work, members, gold)
            res = run_leg(os.path.join(BIN, tool), argv, work,
                          os.path.join(logs, tag))
            post_good, post_bad = gate(work, members, gold)
            strays = remove_strays(work, keep)
            print("LEG round=m5full rep=%d m=%d tool=%s argv='%s' wall=%s cpu=%s "
                  "cpu_over_wall=%s peak_mb=%s rc=%d restored=%d/%d "
                  "damaged_members=%d touched_members=%d blocks_written=%d "
                  "strays=%d seed=%d errlen=%d ts=%s"
                  % (rep, rung, tool, " ".join(argv), res["wall"], res["cpu"],
                     round(res["cpu"] / max(res["wall"], 0.001), 2),
                     res["peak_mb"], res["rc"], post_good, len(members),
                     len(members) - pre_good, len(picks["bym"]), wrote, strays,
                     seed, res["errlen"], utcnow()), flush=True)
            restore_slices(work, pristine, members, SLICE, picks)
            g2, b2 = gate(work, members, gold)
            if g2 != len(members):
                for nm in b2:
                    subprocess.check_call(["cp", os.path.join(pristine, nm),
                                           os.path.join(work, nm)])
                g3, _ = gate(work, members, gold)
                print("RESET rep=%d m=%d tool=%s slice_restore_left=%d "
                      "after_full_copy=%d/%d"
                      % (rep, rung, tool, len(members) - g2, g3, len(members)),
                      flush=True)
                if g3 != len(members):
                    print("M5FULL-FAIL work dir unrecoverable", flush=True)
                    sys.exit(9)
            for nm in parfiles:
                subprocess.check_call(["cp", os.path.join(pristine, nm),
                                       os.path.join(work, nm)])

        for rep in REPS:
            for tool in TOOLS:
                warm(work)
                res = run_leg(os.path.join(BIN, tool), VARGV(tool, len(members)), work,
                              os.path.join(logs, "verify-%s-r%d" % (tool, rep)))
                g, _ = gate(work, members, gold)
                print("VERIFY round=m5full rep=%d tool=%s argv='%s' wall=%s cpu=%s "
                      "cpu_over_wall=%s peak_mb=%s rc=%d intact=%d/%d errlen=%d ts=%s"
                      % (rep, tool, " ".join(VARGV(tool, len(members))), res["wall"], res["cpu"],
                         round(res["cpu"] / max(res["wall"], 0.001), 2),
                         res["peak_mb"], res["rc"], g, len(members),
                         res["errlen"], utcnow()), flush=True)
                remove_strays(work, keep)
            for rung in RUNGS:
                seed = 20260910 + rung * 7 + rep   # identical damage for both tools
                for tool in TOOLS:
                    run_rung(tool, rung, rep, seed,
                             "r%d-m%d-%s" % (rep, rung, tool), RARGV(tool, len(members)))
            print("M5FULL-REP-END rep=%d %s" % (rep, utcnow()), flush=True)
        print("M5FULL-END %s" % utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
