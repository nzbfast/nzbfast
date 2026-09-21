#!/usr/bin/env python3
"""mswp.py - ROUND 4, the create + verify size sweep, re-run on 1.5.0-beta.1.

This is cliswp2's round rebuilt on the current binary. cliswp2's own data is
valid but was measured on parfast 0.90.0-beta.1, which predates TODO 334.

Everything cliswp2 got right is kept and is why it exists:
  - recovery is written IN PLACE. par2cmdline 1.4.0 and turbo 1.5.0 REFUSE a
    recovery path outside the source directory (exit 3), and an earlier round
    published every one of those refusals as a 0.03 second create.
  - rc is captured on every leg, and so is stderr.
  - `-t` is stated explicitly rather than left to a default.
  - every create leg is GATED on recovery size and shape, and the r=20 leg is
    gated by a full CROSS-VERIFY in both directions, which is what proves the
    bytes are a real spec-conformant set rather than a plausible-sized file.
  - per-leg output is kept, one file per leg.

The block size follows PAR2's 32,768-slice cap, which is why the create ratio
is NOT monotone in file size: past the point where 750 KiB slices would exceed
the cap, the slice grows and the work per byte changes.
"""
import os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import RigLock, utcnow, run_leg, box_facts, bin_facts, harness_facts

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
RIG = os.path.join(HOME, "pubrun", "swp")
LOCK = os.path.join(HOME, "pubrun", "swp.lock")
WAIT_LOG = os.path.join(HOME, "pubrun", "lad.log")
WAIT_MARK = None   # unused: see the note in main()
SIZES = [10, 15, 20, 23, 30, 40, 50, 60, 70, 80]
REDS = [10, 15, 20]
THREADS = 32
GIB = 1 << 30
BASE_SLICE = 768000
SLICE_CAP = 32768


def slice_for(g):
    """750 KiB where the whole set fits inside PAR2's 32,768-slice cap,
    otherwise the smallest 4-byte-aligned slice that does."""
    if g * -(-GIB // BASE_SLICE) <= SLICE_CAP:
        return BASE_SLICE
    per = SLICE_CAP // g
    return ((-(-GIB // per)) + 3) // 4 * 4


def main():
    # THIS ROUND IS FIRST IN THE QUEUE and waits on nothing. It used to block on
    # the 15% ladder's MLAD-END marker; that ladder was superseded and its log
    # renamed, so the wait could never be satisfied and the round sat silent for
    # four minutes with an empty log and no lock held - alive, and doing nothing.
    #
    # A marker wait keyed on a FILENAME is only as good as the filename: renaming
    # a log to bank it silently disarms every round waiting on it, and the
    # failure looks exactly like a round that is simply slow to start. The
    # per-box RIG lock, not the marker, is what actually keeps one round at a
    # time; the markers only order them.

    lock = RigLock(LOCK)
    lock.take()
    try:
        print("MSWP-START %s" % utcnow(), flush=True)
        harness_facts()
        box_facts()
        parfast = os.path.join(BIN, "parfast")
        turbo = os.path.join(BIN, "par2turbo")
        bin_facts([parfast, turbo])
        print("PROTOCOL sizes_gib=%s redundancy_pct=%s threads=%d "
              "recovery=in-place verify_reps=2 slice_cap=%d base_slice=%d"
              % (SIZES, REDS, THREADS, SLICE_CAP, BASE_SLICE), flush=True)

        pay = os.path.join(RIG, "pay")
        src = os.path.join(RIG, "s")
        logs = os.path.join(RIG, "logs")
        for d in (pay, src, logs):
            os.makedirs(d, exist_ok=True)
        for i in range(max(SIZES)):
            p = os.path.join(pay, "p%02d.bin" % i)
            if not os.path.exists(p) or os.path.getsize(p) != GIB:
                subprocess.check_call(["dd", "if=/dev/urandom", "of=" + p,
                                       "bs=1048576", "count=1024"],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        print("PAYLOAD-READY members=%d bytes=%d"
              % (max(SIZES), sum(os.path.getsize(os.path.join(pay, f))
                                 for f in os.listdir(pay))), flush=True)

        arms = {"parfast": parfast, "turbo": turbo}
        for g in SIZES:
            bs = slice_for(g)
            blocks = g * -(-GIB // bs)
            subprocess.call(["rm", "-rf", src])
            os.makedirs(src, exist_ok=True)
            members = []
            for i in range(g):
                nm = "p%02d.bin" % i
                os.link(os.path.join(pay, nm), os.path.join(src, nm))
                members.append(nm)
            for r in REDS:
                for arm in ("parfast", "turbo"):
                    for f in os.listdir(src):
                        if f.startswith("pub") and f.endswith(".par2"):
                            os.unlink(os.path.join(src, f))
                    tag = "cc-%d-%d-%s" % (g, r, arm)
                    res = run_leg(arms[arm],
                                  ["c", "-q", "-t%d" % THREADS, "-T%d" % tflag(len(members)),
                                   "-s%d" % bs, "-r%d" % r, "pub.par2"] + members,
                                  src, os.path.join(logs, tag))
                    pf = sorted(f for f in os.listdir(src)
                                if f.startswith("pub") and f.endswith(".par2"))
                    mb = sum(os.path.getsize(os.path.join(src, f)) for f in pf) / (1 << 20)
                    print("CC size=%d red=%d bs=%d blocks=%d arm=%s wall=%s cpu=%s "
                          "cpu_over_wall=%s peak_mb=%s recovery_mb=%d files=%d rc=%d "
                          "errlen=%d ts=%s"
                          % (g, r, bs, blocks, arm, res["wall"], res["cpu"],
                             round(res["cpu"] / max(res["wall"], 0.001), 2),
                             res["peak_mb"], round(mb), len(pf), res["rc"],
                             res["errlen"], utcnow()), flush=True)
                    lo, hi = g * 1024 * r / 100 * 0.90, g * 1024 * r / 100 * 1.25
                    ok = res["rc"] == 0 and len(pf) > 1 and lo <= mb <= hi
                    if not ok:
                        print("GATE-FAIL create size=%d red=%d arm=%s rc=%d "
                              "recovery_mb=%d files=%d" % (g, r, arm, res["rc"],
                                                           round(mb), len(pf)), flush=True)
                    if r == 20 and ok:
                        # the real gate: the OTHER tool must verify this set clean
                        xn = "turbo" if arm == "parfast" else "parfast"
                        xres = run_leg(arms[xn], ["v", "-q", "-t%d" % THREADS, "pub.par2"],
                                       src, os.path.join(logs, "xv-%d-%s-by-%s" % (g, arm, xn)))
                        print("XV size=%d set=%s by=%s rc=%d wall=%s errlen=%d"
                              % (g, arm, xn, xres["rc"], xres["wall"], xres["errlen"]), flush=True)
                        if xres["rc"] != 0:
                            print("GATE-FAIL cross-verify size=%d set=%s by=%s rc=%d"
                                  % (g, arm, xn, xres["rc"]), flush=True)
                        elif arm == "parfast":
                            for vrep in (1, 2):
                                for varm in ("parfast", "turbo"):
                                    vres = run_leg(arms[varm],
                                                   ["v", "-q", "-t%d" % THREADS, "pub.par2"],
                                                   src, os.path.join(logs, "vv-%d-%d-%s" % (g, vrep, varm)))
                                    print("VV size=%d set=parfast rep=%d arm=%s wall=%s "
                                          "cpu=%s cpu_over_wall=%s peak_mb=%s rc=%d errlen=%d ts=%s"
                                          % (g, vrep, varm, vres["wall"], vres["cpu"],
                                             round(vres["cpu"] / max(vres["wall"], 0.001), 2),
                                             vres["peak_mb"], vres["rc"], vres["errlen"],
                                             utcnow()), flush=True)
                                    if vres["rc"] != 0:
                                        print("GATE-FAIL verify size=%d rep=%d arm=%s rc=%d"
                                              % (g, vrep, varm, vres["rc"]), flush=True)
                    for f in os.listdir(src):
                        if f.startswith("pub") and f.endswith(".par2"):
                            os.unlink(os.path.join(src, f))
            subprocess.call(["rm", "-rf", src])
            print("SIZE-DONE %d %s" % (g, utcnow()), flush=True)
        print("MSWP-END %s" % utcnow(), flush=True)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
