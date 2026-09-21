#!/usr/bin/env python3
"""Place a FINE rung ladder across the proportionality band a PINNED ladder
ACTUALLY HAS, read from that ladder's own log in this sitting.

WHY THIS EXISTS, and why it is a script rather than a number typed into a
driver. `rounds/crband-2026-09-18/` placed five 8-row rungs across the
band that `crpool4m` had measured the day before, and MISSED: on an unpinned
arm the band's LOCATION moves 30 rows between sittings while the band itself is
6-35 rows wide, so it cannot be pre-positioned. The fix that round named is a
PINNED arm (which replicates within 5 rows) - but a pinned arm's band still has
to be read IN THE SITTING THAT USES IT, because "pinned replicates within 5"
is a claim about 5 rows and the rung spacing here is 4. So this reads the
crossovers off the log the coarse ladder just wrote and places the fine rungs
off THOSE, never off a banked figure.

IT REFUSES RATHER THAN GUESSES. `rowgate.py`'s `cross()` returns a bare `<N`,
`>N` or `?` when a ladder never crossed in range, and a fine ladder placed off
one of those would be aimed at nothing. Failing to find is failing (CLAUDE.md):
this prints REFUSE and the caller SKIPS that fine ladder and says so in the
round record. It never falls back to crpool4m's band - falling back to a banked
band is precisely the move that cost crband its ladder.

USAGE   bandplan.py <ladder.log> [--rowgate PATH] [--spacing N] [--max-rungs N]
PRINTS  `RUNGS 388,392,...` and a `BAND` line, or `REFUSE <reason>`.
EXIT    0 on a plan, 3 on a refusal, 2 on a usage/IO error.
"""
import math
import re
import subprocess
import sys
from pathlib import Path

SPACING = 4          # the deliverable: an 8-row grid fits only two rungs in 16
MAX_RUNGS = 9        # 36 legs, ~25 min on this part - the sitting's budget
MIN_SPAN = 12        # a band under this is widened so 4-row rungs can bracket it
MAX_SPAN = 40        # wider than this on a PINNED arm contradicts the premise
RUNG_LO, RUNG_HI = 256, 640

CROSS_RE = re.compile(r"crossover .*?CPU m ~ (\S+)\s+wall m ~ (\S+)")


def crossovers(log, rowgate):
    """(cpu, wall) as they come off rowgate - strings, possibly '<384' or '?'."""
    out = subprocess.run([sys.executable, str(rowgate), "read", str(log)],
                         capture_output=True, text=True)
    text = out.stdout + out.stderr
    hits = CROSS_RE.findall(text)
    if not hits:
        return None, None, text
    if len(hits) > 1:
        # (label, threads) grouping gave more than one ladder in this file. A
        # fine ladder aimed at an average of two bands is aimed at neither.
        return "MULTI", "MULTI", text
    return hits[0][0], hits[0][1], text


def plan(cpu, wall, spacing=SPACING, max_rungs=MAX_RUNGS):
    """Rungs across [min,max] of the two crossovers, with a bracket each side."""
    notes = []
    lo, hi = min(cpu, wall), max(cpu, wall)
    if cpu > wall:
        notes.append("INVERTED band: the CPU crossover is ABOVE the wall one "
                     "(%.0f > %.0f), which is the opposite of every banked "
                     "reading on this path - spanning min..max anyway and "
                     "flagging it" % (cpu, wall))
    span = hi - lo
    if span < MIN_SPAN:
        mid = (lo + hi) / 2.0
        lo, hi = mid - MIN_SPAN / 2.0, mid + MIN_SPAN / 2.0
        notes.append("band is %.0f rows, under the %d-row minimum - widened to "
                     "%d centred so 4-row rungs have something to bracket"
                     % (span, MIN_SPAN, MIN_SPAN))
    elif span > MAX_SPAN:
        mid = (lo + hi) / 2.0
        lo, hi = mid - MAX_SPAN / 2.0, mid + MAX_SPAN / 2.0
        notes.append("band is %.0f rows, OVER the %d-row cap expected of a "
                     "pinned arm - capped to %d centred, and the width itself "
                     "is a finding" % (span, MAX_SPAN, MAX_SPAN))
    start = int(math.floor(lo / spacing) * spacing) - spacing
    end = int(math.ceil(hi / spacing) * spacing) + spacing
    rungs = [m for m in range(start, end + 1, spacing) if RUNG_LO <= m <= RUNG_HI]
    while len(rungs) > max_rungs:
        # Trim the OUTER brackets first: the band itself is the deliverable.
        rungs.pop() if (len(rungs) % 2 == 0) else rungs.pop(0)
        notes.append("trimmed to %d rungs to fit the sitting's budget" % max_rungs)
    return rungs, notes


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    opts = dict(a.split("=", 1) for a in argv[1:] if a.startswith("--") and "=" in a)
    if len(args) != 1:
        print("usage: bandplan.py <ladder.log> [--rowgate=PATH] [--spacing=N] [--max-rungs=N]")
        return 2
    log = Path(args[0])
    if not log.exists():
        print("REFUSE no such log: %s" % log)
        return 3
    rowgate = Path(opts.get("--rowgate", Path(__file__).resolve().parents[2] / "harness" / "rowgate.py"))
    if not rowgate.exists():
        print("REFUSE rowgate.py not found at %s" % rowgate)
        return 3
    spacing = int(opts.get("--spacing", SPACING))
    max_rungs = int(opts.get("--max-rungs", MAX_RUNGS))

    cpu_s, wall_s, text = crossovers(log, rowgate)
    if cpu_s is None:
        print("REFUSE rowgate printed no crossover line for %s - the ladder "
              "produced no readable table (it answers 'REFUSED: no legs' on a "
              "UTF-16 log, which is the usual cause)" % log.name)
        return 3
    if cpu_s == "MULTI":
        print("REFUSE %s holds more than one (label, threads) ladder - a fine "
              "ladder aimed at an average of two bands is aimed at neither" % log.name)
        return 3
    try:
        cpu, wall = float(cpu_s), float(wall_s)
    except ValueError:
        print("REFUSE %s did not cross in range: CPU m ~ %s, wall m ~ %s. A "
              "fine ladder cannot be aimed at a band with an open end, and "
              "falling back to a BANKED band is the exact move that cost "
              "crband its ladder." % (log.name, cpu_s, wall_s))
        return 3

    rungs, notes = plan(cpu, wall, spacing, max_rungs)
    if len(rungs) < 3:
        print("REFUSE plan came out at %d rung(s) - not enough to bracket "
              "anything" % len(rungs))
        return 3
    print("BAND cpu=%s wall=%s width=%.0f rows  spacing=%d" % (cpu_s, wall_s, abs(wall - cpu), spacing))
    for n in dict.fromkeys(notes):
        print("NOTE %s" % n)
    print("RUNGS %s" % ",".join(str(m) for m in rungs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
