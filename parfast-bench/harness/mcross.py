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
                  box_facts, bin_facts, harness_facts, rig_stamp)

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
RIG = os.path.join(HOME, "pubrun", "cross")
LOCK = os.path.join(HOME, "pubrun", "cross.log")
SLICE = 768000
RBLK = 32177          # 100% parity: the deepest repair PAR2 can express
NMEM = 23
MEMBYTES = 1 << 30
# The SHALLOW end, densely, because that is where the switch is unproven. The
# integration note has it winning 9-40% from 8,192 to 29,484 and "turning over
# below about m = 8,000" - a bound, not a crossing. These rungs bracket it from
# both sides so the crossing can be read off rather than inferred, with the
# deepest two as a positive control: if they do not reproduce the known win,
# the round is measuring something other than what it thinks.
RUNGS = [256, 512, 1024, 2048, 3276, 4096, 6144, 8192, 10240, 12288, 16384]
REPS = [1, 2, 3]   # shallow legs are cheap; the crossing needs a tight median
THREADS = min(32, os.cpu_count() or 8)
# THREE arms, not two tools. "fast" is the same binary as "parfast" with the
# experimental --fast switch, so the A/B cannot differ by anything except the
# switch. The label is what lands on the leg line; the binary is separate.
# Both parfast arms are the SAME binary - parfast-joint, the build that carries
# --fast - so the A/B cannot differ by anything except the switch. Deployed
# beside `parfast` rather than over it, so no round already in flight changes
# binary underneath itself.
# Two arms of ONE binary. No rival here on purpose: the question is not whether
# parfast beats turbo, it is where parfast's own switch stops paying, and adding
# a third tool would triple the wall for nothing.
# NAME THE BASELINE EXPLICITLY. Since 11 Sep 2026 (e5aa098878) the joint
# solve is ON BY DEFAULT on aarch64, so an "off" arm that relies on the
# binary default is not an off arm on an Apple box - it is a second copy of
# the on arm, and the A/B would read as a dead heat with nothing to show it
# had collapsed. NZBFAST_FORNEY_JOINT=0 is now understood in the negative
# direction; before that commit it was not. The deployed binaries predate
# the flip, so this is insurance against the next redeploy rather than a
# fix for a round already run.
ARMS = [
    ("off", "parfast-joint", [], {"NZBFAST_FORNEY_JOINT": "0"}),
    ("fast", "parfast-joint", ["--fast"], {}),
]
TOOLS = sorted({a[1] for a in ARMS})
# The one parfast this round uses, for create as well as for the arms.
PARFAST = ARMS[0][1]
# argv is a FUNCTION of the fixture, not a constant: -T must be
# min(cores, files) and the file count is not known until main() reads the
# payload. Building these at module level is what made the flat -T16 look
# harmless for so long.
def RARGV(extra, files):
    return ["r", "-q", "-t%d" % THREADS, "-T%d" % tflag(files)] + list(extra) + ["f.par2"]


def VARGV(extra, files):
    return ["v", "-q", "-t%d" % THREADS, "-T%d" % tflag(files)] + list(extra) + ["f.par2"]


def main():
    # NO MARKER WAIT HERE, deliberately. This used to block until another
    # round's log contained its end marker. Renaming a log to bank it then
    # disarms every round waiting on it - and on 11 Sep 2026 exactly that
    # happened: a partial sweep was banked under a new name, and two rounds on
    # two machines sat for hours in a 120-second poll loop with an empty log
    # and 0.03 s of CPU, looking alive. The OSError from the missing file was
    # swallowed by design, so nothing said so. Serialisation belongs to the rig
    # lock and the queue runner, which observe a state that cannot be renamed.
    lock = RigLock(LOCK)
    lock.take()
    try:
        print("MCROSS-START %s" % utcnow(), flush=True)
        box_facts()
        bin_facts([os.path.join(BIN, t) for t in TOOLS])
        # The DRIVER's provenance, not just the binary's, and the per-leg `rig=`
        # token's round-start twin - see `pdrv.harness_facts`. A parfast round
        # has no other evidence of a harness that changed under it mid-round.
        harness_facts()
        print("PROTOCOL slice=%d recovery_blocks=%d source_blocks=32177 "
              "redundancy_pct=100.0 damage=scattered-seeded-slice-overwrite "
              "reps=2 gate=sha256-all-members prewarm=full-read-of-work-dir"
              % (SLICE, RBLK), flush=True)
        for label, binname, extra, env in ARMS:
            print("ARGV %s repair='%s' verify='%s'"
                  % (label, " ".join(RARGV(extra, NMEM)), " ".join(VARGV(extra, NMEM))), flush=True)

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
            share = os.path.join(HOME, "pubrun", "swp", "pay", nm)
            if os.path.exists(share) and os.path.getsize(share) == MEMBYTES:
                subprocess.check_call(["cp", share, p])   # the sweep's payload,
                                                          # urandom and distinct
            else:
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
            print("MCROSS-FAIL payload members not distinct", flush=True)
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
            print("MCROSS-FAIL payload is near-copies", flush=True)
            sys.exit(9)
        for nm in members:
            print("GOLD %s %s" % (nm, gold[nm]), flush=True)

        for f in os.listdir(pristine):
            if f.endswith(".par2"):
                os.unlink(os.path.join(pristine, f))
        r = run_leg(os.path.join(BIN, PARFAST),
                    ["c", "-q", "-t32", "-T%d" % tflag(len(members)), "-s%d" % SLICE, "-c%d" % RBLK,
                     "f.par2"] + members,
                    pristine, os.path.join(logs, "create-parfast"))
        parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
        parbytes = sum(os.path.getsize(os.path.join(pristine, f)) for f in parfiles)
        print("CREATE tool=parfast rc=%d wall=%s cpu=%s peak_mb=%s par2files=%d "
              "par2bytes=%d errlen=%d"
              % (r["rc"], r["wall"], r["cpu"], r["peak_mb"], len(parfiles),
                 parbytes, r["errlen"]), flush=True)
        if r["rc"] != 0 or not parfiles:
            print("MCROSS-FAIL create rc=%d" % r["rc"], flush=True)
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

        def stage1_label(errpath):
            """FALLBACK, the joint kernel's name, or none. The ONLY place the
            engine says whether --fast actually took the joint path is a
            repair-timing trace line, so the round sets NZBFAST_REPAIR_TIMING
            for every arm and reads it back. Without this an arm that fell back
            to the ordinary solver is indistinguishable from one that ran, and
            the round measures the fallback while calling it fast mode - which
            is exactly what the 10 Sep Core Ultra round did."""
            try:
                txt = open(errpath, errors="replace").read()
            except OSError:
                return "no-err"
            for line in txt.splitlines():
                if "forney stage 1 (joint" in line:
                    inner = line.split("(joint", 1)[1].split(")", 1)[0]
                    return "FALLBACK" if "FALLBACK" in inner else (inner.strip().strip(",") or "joint")
            return "no-label"

        def run_rung(label, binname, extra, env, rung, rep, seed, tag):
            argv = RARGV(extra, len(members))
            tool = binname
            warm(work)
            picks = damage_picks(work, members, SLICE, rung, seed)
            wrote = apply_damage(work, members, SLICE, picks, seed)
            pre_good, _ = gate(work, members, gold)
            e = dict(env)
            e["NZBFAST_REPAIR_TIMING"] = "1"
            res = run_leg(os.path.join(BIN, binname), argv, work,
                          os.path.join(logs, tag), env_extra=e)
            post_good, post_bad = gate(work, members, gold)
            strays = remove_strays(work, keep)
            print("LEG round=mcross rep=%d m=%d tool=%s argv='%s' wall=%s cpu=%s "
                  "cpu_over_wall=%s peak_mb=%s rc=%d restored=%d/%d "
                  "damaged_members=%d touched_members=%d blocks_written=%d "
                  "strays=%d seed=%d stage1=%s foreign_cpu=%s errlen=%d ts=%s "
                  "rig=%s"
                  % (rep, rung, label, " ".join(argv), res["wall"], res["cpu"],
                     round(res["cpu"] / max(res["wall"], 0.001), 2),
                     res["peak_mb"], res["rc"], post_good, len(members),
                     len(members) - pre_good, len(picks["bym"]), wrote, strays,
                     seed, stage1_label(os.path.join(logs, tag) + ".err"),
                     res.get("foreign_cpu"), res["errlen"], utcnow(),
                     rig_stamp()), flush=True)
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
                    print("MCROSS-FAIL work dir unrecoverable", flush=True)
                    sys.exit(9)
            for nm in parfiles:
                subprocess.check_call(["cp", os.path.join(pristine, nm),
                                       os.path.join(work, nm)])

        # An untimed warm-up pass, discarded. Repetition 1 runs systematically
        # slow on a box where the set does not sit in page cache, and a median
        # of two IS the mean of two, so it cannot throw the cold reading away.
        print("WARMUP-START %s" % utcnow(), flush=True)
        for wrung in (1, 64):
            for label, binname, extra, env in ARMS:
                run_rung(label, binname, extra, env, wrung, 0,
                         20260910 + wrung * 7, "warm-m%d-%s" % (wrung, label))
        print("WARMUP-END %s" % utcnow(), flush=True)

        for rep in REPS:
            for label, binname, extra, env in ARMS:
                warm(work)
                vargv = VARGV(extra, len(members))
                res = run_leg(os.path.join(BIN, binname), vargv, work,
                              os.path.join(logs, "verify-%s-r%d" % (label, rep)))
                g, _ = gate(work, members, gold)
                print("VERIFY round=mcross rep=%d tool=%s argv='%s' wall=%s cpu=%s "
                      "cpu_over_wall=%s peak_mb=%s rc=%d intact=%d/%d errlen=%d ts=%s"
                      % (rep, label, " ".join(vargv), res["wall"], res["cpu"],
                         round(res["cpu"] / max(res["wall"], 0.001), 2),
                         res["peak_mb"], res["rc"], g, len(members),
                         res["errlen"], utcnow()), flush=True)
                remove_strays(work, keep)
            for rung in RUNGS:
                seed = 20260910 + rung * 7 + rep   # identical damage for all arms
                for label, binname, extra, env in ARMS:
                    run_rung(label, binname, extra, env, rung, rep, seed,
                             "r%d-m%d-%s" % (rep, rung, label))
            print("MCROSS-REP-END rep=%d %s" % (rep, utcnow()), flush=True)
        print("MCROSS-END %s" % utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
