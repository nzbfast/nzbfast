#!/usr/bin/env python3
"""Start jcross.py detached, logging to ~/pubrun/<tag>.log.

`detach.py` is hardwired to mqueue.py; this is the same trick for a round
launched directly. macOS ships no setsid(1), and `nohup ... &` alone is not
enough: pdrv installs a SIGHUP handler at import that overrides the SIG_IGN
nohup set, so the round took the hangup when the launching ssh closed. A new
session makes the round its own leader, so the hangup is never delivered.

    jlaunch.py <tag> [args passed through to jcross.py]
"""
import os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
tag = sys.argv[1]
log = os.path.join(here, "%s.log" % tag)
if os.path.exists(log):
    sys.exit("refusing to overwrite %s - bank it first" % log)
with open(log, "w") as fh, open(os.devnull) as devnull:
    p = subprocess.Popen([sys.executable, os.path.join(here, "jcross.py"),
                          "--tag", tag] + sys.argv[2:],
                         cwd=here, stdout=fh, stderr=subprocess.STDOUT,
                         stdin=devnull, start_new_session=True)
print("DETACHED pid=%d tag=%s log=%s" % (p.pid, tag, log))
