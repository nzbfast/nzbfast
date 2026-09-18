#!/usr/bin/env python3
"""phases.py LEG.err... - footprint / repair-work high-water per phase of a leg,
plus each slab's SOLVE interval on its own.

Phase boundaries are the repair-timing totals (seconds since the repair's t0,
a few ms after the mem-floor sampler's clock - close enough for 25 ms bins):
each `feed+fold+solve: ... (total T)` closes a slab, then `patch`, then
`final verify`. A slab's solve is `[T - D, T]`, D being that slab's
`back-substitution (label): D` - the repair-work gauge there is what the
solve itself holds (syndromes / T / output / arenas), unmasked by the feed.
"""
import re, sys

def secs(v, u):
    return float(v) * {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}[u]

for path in sys.argv[1:]:
    err = open(path, errors="replace").read()
    series = [(float(t), int(fp), int(wk)) for t, fp, wk in
              re.findall(r"mem-floor series: ([0-9.]+)s fp (\d+) MB work (\d+) MB", err)]
    bs = [secs(v, u) for v, u in re.findall(r"back-substitution \([^)]*\): ([0-9.]+)(µs|ms|s)", err)]
    bounds, solves, n = [], [], 0
    for label, v, u in re.findall(r"(feed\+fold\+solve|patch|final verify): \+[0-9.]+(?:µs|ms|s) \(total ([0-9.]+)(µs|ms|s)\)", err):
        t = secs(v, u)
        if label == "feed+fold+solve":
            if n < len(bs):
                solves.append((t - bs[n], t))
            n += 1
            bounds.append(("slab%d" % n, t))
        else:
            bounds.append((label.replace("final ", ""), t))
    def hw(lo, hi):
        seg = [s for s in series if lo <= s[0] < hi]
        return (max(s[1] for s in seg), max(s[2] for s in seg), len(seg)) if seg else None
    out, lo = [], 0.0
    for name, hi in bounds + [("tail", float("inf"))]:
        h = hw(lo, hi)
        if h:
            out.append("%s fp %d/w %d" % (name, h[0], h[1]))
        lo = hi
    sol = []
    for i, (a, b) in enumerate(solves):
        h = hw(a, b + 0.03)
        sol.append("s%d %.2fs fp %s/w %s" % (i + 1, b - a, h[0] if h else "-", h[1] if h else "-"))
    tag = path.rsplit("/", 1)[-1].replace(".err", "")
    rss = re.search(r"ru_maxrss (\d+) MB", err)
    print("%-24s rss %4s | %s\n%24s SOLVE | %s" % (tag, rss.group(1) if rss else "?", " | ".join(out), "", " | ".join(sol) or "-"))
