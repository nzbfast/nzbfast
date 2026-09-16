#!/usr/bin/env python3
"""Attribute a macOS `sample` call tree over the DECODE threads.

Written 16 Sep 2026 for the pending_r residue chip
(research/PENDING-R-RESIDUE-2026-09-16.md); the raw sample comes from
bench/nested-corpus/sample-decode.sh.

`sample` reports per-thread trees with counts, and the engine names its
decode threads `decode-N`, which is what makes this separable at all.
Two readings come out:

  * the LOCK-TAKING SITE above each `__psynch_mutexwait` leaf, which is
    the only way to tell one mutex from another - every wait bottoms out
    in the same kernel frame, so "78% in __psynch_mutexwait" on its own
    names nothing;
  * the inclusive share of named frames of interest, which survives
    inlining better than the leaf does.

WHY BOTH. `flush_pending_r` is inlined into `decode_consumer_loop` in a
release build, so the `pending_r` acquisition at the top of the flush is
attributed to the CALLER and a filter on the callee's name misses most
of it. Round 23 of research/RAR-PERF-AUDIT-2026-09-02.md hit this and
said so; the 16 Sep lane hit it again and lost a reading to it before
reading that sentence.

THE DENOMINATOR IS WALL, NOT WORK. These are wall-clock thread samples:
a descheduled thread is sampled exactly like a working one, so on an
oversubscribed box the mutex shares inflate together and mean much less
than they look. Read a shape-vs-control DIFFERENCE, never an absolute,
and price anything that matters with instructions retired instead.

`--self` IS THE THIRD READING, AND THE ONE AN ATTRIBUTION ROUND WANTS.
The two above answer "what is this thread waiting on"; neither answers
"where does the work go", because `sample`'s tree counts are INCLUSIVE
and a caller's number is dominated by whatever it called. `--self`
subtracts each frame's children from it, which turns the tree into a
leaf histogram, and splits that histogram in two: the BLOCKED leaves
(every `__psynch_*` / `ulock_wait` / `kevent` / `semaphore_wait_trap` /
`semwait_signal` wait) and everything else. On this fleet the blocked
half is 85-95% of all samples on EVERY shape including a one-member
control, so it is the non-blocked half that separates shapes at all -
and a percentage of the non-blocked half is the only share worth
differencing. Use it with `--threads ""` (the whole process): round 26
of research/RAR-PERF-AUDIT-2026-09-02.md found the per-member cost
living in the post-download tail, where there is no `decode-N` thread
to filter to, so the default filter would have hidden it.

STILL A WALL DENOMINATOR. `--self` makes the histogram readable; it does
not make it a work measurement. Difference it against a control to pick
a SITE, then price that site with instructions retired.

  decode-sample-attr.py <sample.txt> [--threads decode-] [--top N]
  decode-sample-attr.py <sample.txt> --threads "" --self --top 25
"""
import re, sys, argparse

ap = argparse.ArgumentParser()
ap.add_argument("file")
ap.add_argument("--threads", default="decode-")
ap.add_argument("--top", type=int, default=10)
ap.add_argument("--self", dest="selfmode", action="store_true",
                help="leaf/self-sample histogram, blocked and non-blocked split")
ap.add_argument("--interest", action="append", default=None,
                help="substring to report inclusively; repeatable")
a = ap.parse_args()
KEYS = a.interest or ["flush_pending_r", "retain", "materialized",
                      "drain_late", "decode_consumer_loop"]

hdr = re.compile(r"^\s{4}(\d+) Thread_\w+:?\s*(.*)$")
# gutter is whitespace plus the `+ ! : |` tree characters; the column of
# the sample count is the frame depth.
frame = re.compile(r"^([ +!:|]*)(\d+) (.*)$")
def sym(s):
    return s.split("  (in ")[0].strip() if "  (in " in s else s.strip()

lines = open(a.file, errors="replace").read().splitlines()
cur, stack, tot = None, [], 0
parents, interest, selfh = {}, {}, {}
for ln in lines:
    h = hdr.match(ln)
    if h:
        nm = h.group(2).strip()
        cur = nm if a.threads in nm else None
        if cur:
            tot += int(h.group(1))
        while stack:
            _, ps, pn, pc = stack.pop()
            selfh[ps] = selfh.get(ps, 0) + (pn - pc)
        stack = []
        continue
    if not cur:
        continue
    m = frame.match(ln)
    if not m:
        continue
    d, n, s = len(m.group(1)), int(m.group(2)), sym(m.group(3))
    # Tree counts are INCLUSIVE, so a frame's own cost is its count less
    # its children's. Closing a frame is the moment its children are all
    # known, which is when the stack unwinds past it.
    while stack and stack[-1][0] >= d:
        _, ps, pn, pc = stack.pop()
        selfh[ps] = selfh.get(ps, 0) + (pn - pc)
    if stack:
        stack[-1][3] += n
    stack.append([d, s, n, 0])
    for k in KEYS:
        if k in s:
            interest[k] = interest.get(k, 0) + n
    if "__psynch_mutexwait" in s:
        anc = [x[1] for x in stack[:-1]]
        p = next((x for x in reversed(anc)
                  if not x.startswith(("_pthread", "__psynch"))), "?")
        parents[p] = parents.get(p, 0) + n

if not tot:
    sys.exit(f"no threads matching {a.threads!r} in {a.file} - "
             "did sample-decode.sh sample the time(1) shim instead of nzbfast?")

if a.selfmode:
    # Every leaf a thread can be parked in. Kept as a NAMED list rather
    # than a "starts with __" test: `__strip_prefix` is a hot working
    # frame on these shapes and a prefix rule would score it as a wait.
    # `kevent` IS ON THIS LIST AND MUST STAY ON IT. The bare spelling is
    # the tokio reactor parked in its poll, not work: on a 16 Sep leg it
    # was 59% of the non-blocked column on `manysmall` and 95% on the
    # one-member control, which buries every real frame under it and -
    # worse - makes the CONTROL look busy. It is spelled without
    # underscores, so an `__`-prefixed list misses it; that is exactly
    # how it got through the first reading of that leg.
    WAIT = ("__psynch_cvwait", "__psynch_mutexwait", "__ulock_wait",
            "kevent", "semaphore_wait_trap", "__semwait_signal",
            "__sigsuspend", "__wait4", "mach_msg2_trap", "__select",
            "__psynch_rw_rdlock", "__psynch_rw_wrlock", "__accept",
            "_pthread_cond_wait", "park_internal")
    blocked = sum(n for f, n in selfh.items() if any(w in f for w in WAIT))
    live = tot - blocked
    print(f"{a.file.split('/')[-1]}  threads {a.threads!r}: {tot} samples")
    print(f"  blocked (wait leaves): {blocked} = {100*blocked/tot:.1f}%")
    print(f"  NON-BLOCKED:           {live} = {100*live/tot:.1f}%   "
          "<- the only column worth differencing")
    print("  self samples, non-blocked, by frame:")
    for f, n in sorted(selfh.items(), key=lambda kv: -kv[1]):
        if any(w in f for w in WAIT):
            continue
        if n <= 0:
            continue
        print(f"    {100*n/live:6.2f}% of live  {100*n/tot:6.3f}% of all  "
              f"{n:7d}  {f[:100]}")
        a.top -= 1
        if a.top <= 0:
            break
    sys.exit(0)
mw = sum(parents.values())
print(f"{a.file.split('/')[-1]}  decode threads total: {tot} samples")
print(f"  __psynch_mutexwait (ANY mutex): {mw} = {100*mw/tot:.1f}%")
print("  lock-taking site above the wait:")
for p, n in sorted(parents.items(), key=lambda kv: -kv[1])[:a.top]:
    print(f"    {100*n/tot:6.2f}%  {n:7d}  {p[:110]}")
print("  inclusive share of frames of interest:")
for k in KEYS:
    n = interest.get(k, 0)
    print(f"    {100*n/tot:6.2f}%  {n:7d}  {k}")
