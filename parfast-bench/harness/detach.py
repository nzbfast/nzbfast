#!/usr/bin/env python3
"""Start a round in its own session, detached from the ssh that launched it.

macOS ships no setsid(1), and `nohup ... &` alone was not enough here: pdrv
installed a SIGHUP handler at import, which overrode the SIG_IGN nohup had set,
so the round took the hangup when the launching ssh closed. That is fixed in
pdrv, and this belt-and-braces makes the round its own session leader so the
hangup is never delivered in the first place.
"""
import os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
log = os.path.join(here, "mqueue.log")
with open(log, "w") as fh, open(os.devnull) as devnull:
    p = subprocess.Popen([sys.executable, os.path.join(here, "mqueue.py")] + sys.argv[1:],
                         cwd=here, stdout=fh, stderr=subprocess.STDOUT,
                         stdin=devnull, start_new_session=True)
print("DETACHED pid=%d rounds=%s" % (p.pid, " ".join(sys.argv[1:])))
