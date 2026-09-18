#!/usr/bin/env python3
"""Start a round only once the box is actually quiet.

Not a scheduler: a REFUSAL that retries. It polls foreign CPU with the same
sampler the leg guard uses, so "quiet enough to start" and "quiet enough to
time" are one definition rather than two that can drift apart. It also names
the biggest foreign consumer in every wait line, because the 10 Sep 2026
incident was ten minutes of a neighbouring lane that nothing in either log
mentioned - a wait that cannot say WHO it is waiting for teaches nobody.
"""
import os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pdrv
import riglock_state

script = sys.argv[1]
logpath = sys.argv[2]
max_wait_s = int(sys.argv[3]) if len(sys.argv) > 3 else 6 * 3600

deadline = time.time() + max_wait_s
while time.time() < deadline:
    total, top = pdrv.foreign_cpu()
    ceiling = pdrv.foreign_ceiling()
    percore, _ = pdrv.foreign_cpu_window()
    # The rig lock's HOLDER, never the rig lock's existence: this was
    # `os.path.exists(...)` until 16 Sep 2026, which is the same defect that
    # held apple-m3-ultra for eight hours against a zero-byte file nobody owned - and
    # here it would have burned this script's whole six-hour budget without
    # ever starting the round. riglock_state is the one place that decides.
    # No announcement from here: the round that TAKES the lock clears the
    # orphan and says so, under the flock, which is the only safe place to.
    # THE /3.0 IS pdrv's WARN ARM, PROMOTED TO A REFUSAL - it is not a third
    # threshold somebody invented here, which is what it looked like when it
    # carried no comment (and what the 16 Sep handoff reasonably flagged it as).
    # `require_quiet_box` aborts at `ceiling` and prints WARN-FOREIGN-CPU from
    # `ceiling / 3.0` up, so ceiling/3 is already this module's name for "over
    # the noise floor, under the refusal". A START gate can afford to insist on
    # the stricter of the two, because it has six hours of patience and nothing
    # invested yet; the per-leg guard cannot, because by then the round has paid
    # for its fixture. One quantity, two budgets. DECIDED 16 Sep 2026 and KEPT,
    # rather than inherited.
    #
    # NO BLOCKING PER-CORE ARM HERE, DELIBERATELY. pdrv's per-core arm is
    # non-blocking on purpose (see PER_CORE_CEILING_PCT), and a blocking one at
    # THIS site would be worse than nothing: apple-m1-ultra-64gb was measured on 16 Sep
    # with WindowServer resident at 43-46% of one core across ten consecutive
    # samples, so a start gate refusing at 25 would spend its whole six hour
    # budget and exit 19 without ever starting a round on that box. The reading
    # is printed on every line instead, so the decision to start is on the
    # record with the quantity that would have changed it, and the per-leg
    # guard flags it on each leg.
    if total < ceiling / 3.0 and riglock_state.lock_state()[0] != "held":
        print("BOX-QUIET foreign_cpu=%.0f%% foreign_1core=%.0f%% starting %s at %s"
              % (total, percore, script, pdrv.utcnow()), flush=True)
        os.execvp(sys.executable, [sys.executable, script])
    who = top[0] if top else (0, 0, "-")
    print("WAIT foreign_cpu=%.0f%% ceiling=%.0f%% foreign_1core=%.0f%% top=%s(%d)=%.0f%% ts=%s"
          % (total, ceiling, percore, who[2], who[1], who[0], pdrv.utcnow()), flush=True)
    time.sleep(60)
print("WAIT-TIMEOUT %s never went quiet in %ds" % (script, max_wait_s), flush=True)
sys.exit(19)
