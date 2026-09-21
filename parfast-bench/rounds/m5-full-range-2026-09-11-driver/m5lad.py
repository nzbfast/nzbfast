#!/usr/bin/env python3
"""mlad.py - ROUND 3, the Apple repair ladder, same fixture shape as the i5.

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

HOME = os.path.expanduser("~")
BIN = os.path.join(HOME, "pubrun", "bin")
RIG = os.path.join(HOME, "pubrun", "lad")
LOCK = os.path.join(HOME, "pubrun", "lad.lock")
SLICE = 768000
RBLK = 2098          # 14.996% of 13,990 source blocks
NMEM = 10
MEMBYTES = 1 << 30
RUNGS = [1, 16, 64, 256, 512, 640, 704, 768, 896, 1024, 1152, 1280, 1408,
         1600, 1792, 2048, 2098]
REPS = [1, 2]
TOOLS = ["parfast", "par2turbo"]
RARGV = {"parfast": ["r", "-q", "-t18", "-T16", "f.par2"],
         "par2turbo": ["r", "-q", "-t18", "-T16", "f.par2"]}
VARGV = {"parfast": ["v", "-q", "-t18", "-T16", "f.par2"],
         "par2turbo": ["v", "-q", "-t18", "-T16", "f.par2"]}


def main():
    lock = RigLock(LOCK)
    lock.take()
    try:
        print("MLAD-START %s" % utcnow(), flush=True)
        harness_facts()
        box_facts()
        bin_facts([os.path.join(BIN, t) for t in TOOLS])
        print("PROTOCOL slice=%d recovery_blocks=%d source_blocks=13990 "
              "redundancy_pct=14.996 damage=scattered-seeded-slice-overwrite "
              "reps=2 gate=sha256-all-members prewarm=full-read-of-work-dir"
              % (SLICE, RBLK), flush=True)
        for t in TOOLS:
            print("ARGV %s repair='%s' verify='%s'"
                  % (t, " ".join(RARGV[t]), " ".join(VARGV[t])), flush=True)

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
                                   "bs=1m", "count=1024"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        gold = {nm: sha256_file(os.path.join(pristine, nm)) for nm in members}
        print("FIXTURE members=%d distinct_member_sha=%d/%d bytes=%d"
              % (len(members), len(set(gold.values())), len(members),
                 sum(os.path.getsize(os.path.join(pristine, m)) for m in members)),
              flush=True)
        if len(set(gold.values())) != len(members):
            print("MLAD-FAIL payload members not distinct", flush=True)
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
            print("MLAD-FAIL payload is near-copies", flush=True)
            sys.exit(9)
        for nm in members:
            print("GOLD %s %s" % (nm, gold[nm]), flush=True)

        for f in os.listdir(pristine):
            if f.endswith(".par2"):
                os.unlink(os.path.join(pristine, f))
        r = run_leg(os.path.join(BIN, "parfast"),
                    ["c", "-q", "-t18", "-T16", "-s%d" % SLICE, "-c%d" % RBLK,
                     "f.par2"] + members,
                    pristine, os.path.join(logs, "create-parfast"))
        parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
        parbytes = sum(os.path.getsize(os.path.join(pristine, f)) for f in parfiles)
        print("CREATE tool=parfast rc=%d wall=%s cpu=%s peak_mb=%s par2files=%d "
              "par2bytes=%d errlen=%d"
              % (r["rc"], r["wall"], r["cpu"], r["peak_mb"], len(parfiles),
                 parbytes, r["errlen"]), flush=True)
        if r["rc"] != 0 or not parfiles:
            print("MLAD-FAIL create rc=%d" % r["rc"], flush=True)
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
            print("LEG round=m5lad rep=%d m=%d tool=%s argv='%s' wall=%s cpu=%s "
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
                    print("MLAD-FAIL work dir unrecoverable", flush=True)
                    sys.exit(9)
            for nm in parfiles:
                subprocess.check_call(["cp", os.path.join(pristine, nm),
                                       os.path.join(work, nm)])

        for rep in REPS:
            for tool in TOOLS:
                warm(work)
                res = run_leg(os.path.join(BIN, tool), VARGV[tool], work,
                              os.path.join(logs, "verify-%s-r%d" % (tool, rep)))
                g, _ = gate(work, members, gold)
                print("VERIFY round=m5lad rep=%d tool=%s argv='%s' wall=%s cpu=%s "
                      "cpu_over_wall=%s peak_mb=%s rc=%d intact=%d/%d errlen=%d ts=%s"
                      % (rep, tool, " ".join(VARGV[tool]), res["wall"], res["cpu"],
                         round(res["cpu"] / max(res["wall"], 0.001), 2),
                         res["peak_mb"], res["rc"], g, len(members),
                         res["errlen"], utcnow()), flush=True)
                remove_strays(work, keep)
            for rung in RUNGS:
                seed = 20260910 + rung * 7 + rep   # identical damage for both tools
                for tool in TOOLS:
                    run_rung(tool, rung, rep, seed,
                             "r%d-m%d-%s" % (rep, rung, tool), RARGV[tool])
            print("MLAD-REP-END rep=%d %s" % (rep, utcnow()), flush=True)
        print("MLAD-END %s" % utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
