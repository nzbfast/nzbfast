#!/usr/bin/env python3
"""detachq.py - detach.py's twin for a round that must WAIT for a quiet box.
Same session split as detach.py, one extra hop: waitquiet.py polls the same
foreign-CPU sampler the leg guard uses and execs the round only when the box
is under a third of the ceiling and no rig lock is held. Argument: the round
script. Its own chatter goes to <round>-wait.log; the round writes its own log."""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
script = sys.argv[1]
wait_s = sys.argv[2] if len(sys.argv) > 2 else "21600"
tag = os.path.splitext(os.path.basename(script))[0]
out = open(os.path.join(here, tag + "-wait.log"), "a")
p = subprocess.Popen([sys.executable, os.path.join(here, "waitquiet.py"), os.path.join(here, script), os.path.join(here, tag + ".log"), wait_s],
                     stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True, cwd=here)
print("DETACHED-WAITING pid=%d script=%s max_wait_s=%s" % (p.pid, script, wait_s))
