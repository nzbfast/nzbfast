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

script = sys.argv[1]
logpath = sys.argv[2]
max_wait_s = int(sys.argv[3]) if len(sys.argv) > 3 else 6 * 3600

deadline = time.time() + max_wait_s
while time.time() < deadline:
    total, top = pdrv.foreign_cpu()
    ceiling = pdrv.foreign_ceiling()
    if total < ceiling / 3.0 and not os.path.exists(os.path.expanduser("~/.parfast-rig.lock")):
        print("BOX-QUIET foreign_cpu=%.0f%% starting %s at %s"
              % (total, script, pdrv.utcnow()), flush=True)
        os.execvp(sys.executable, [sys.executable, script])
    who = top[0] if top else (0, 0, "-")
    print("WAIT foreign_cpu=%.0f%% ceiling=%.0f%% top=%s(%d)=%.0f%% ts=%s"
          % (total, ceiling, who[2], who[1], who[0], pdrv.utcnow()), flush=True)
    time.sleep(60)
print("WAIT-TIMEOUT %s never went quiet in %ds" % (script, max_wait_s), flush=True)
sys.exit(19)
