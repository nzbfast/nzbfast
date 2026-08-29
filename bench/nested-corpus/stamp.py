#!/usr/bin/env python3
"""stamp.py - prefix each line of stdin with seconds since this process
started, and pass it through.  The per-phase timeline for the clients that
announce their phases on stdout rather than over an API.

    <client> ... 2>&1 | stamp.py > leg.log

WHY ARRIVAL TIME IS THE RIGHT CLOCK HERE, and where it is not.  Both
clients stamped this way - nzbfast and Weaver - are Rust, and Rust's
`std::io::Stdout` is a LineWriter whatever it is connected to, so it
flushes on every newline and arrival time IS emit time to within a pipe
write.  That is NOT true in general: a C or Python client block-buffers
when its stdout is a pipe, and every line of a 4 KB block would then
carry the timestamp of the block's flush.  NZBGet and rustnzb are
therefore NOT stamped - they write their own log files with their own
timestamps, which is strictly better, and SABnzbd is polled over its API
because its per-slot status and `labels` are the phase signal and its log
is not.

Line-buffered on our side too (`flush=True`), so a tail of a running
leg is live rather than a block behind.
"""

import sys
import time

t0 = time.time()
for line in sys.stdin:
    sys.stdout.write("%8.3f  %s" % (time.time() - t0, line))
    sys.stdout.flush()
