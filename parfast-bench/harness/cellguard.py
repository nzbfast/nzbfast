#!/usr/bin/env python3
"""The one copy of the bimodal-cell rule the A/B drivers all read.

WHAT THIS IS FOR, and the incident that bought it.

an internal note section 12 established
that a bench box - `apple-m1-ultra-128gb` - intermittently confines a timed process
to its four efficiency cores, costing a FLAT 7.2x to 7.5x in wall and
inflating the process's own user+sys 3.9x to 6.1x alongside it. The state
comes and goes on a scale of minutes, so a box that crosses into or out of it
DURING a cell leaves that cell's runs bimodal: some ran healthy, some ran
demoted, and the median lands between the two modes and reads as an ordinary
number.

The tell was already being PRINTED by every driver in this family and nothing
read it: a `min` far below the `median` in the same cell. Two real examples:

  16 Sep, the cell that started the investigation:
      min 489.6 under median 764.1, span reaching 5375.3   -> ratio 0.641
  17 Sep, the same box reproducing it:
      min 740.0 under median 6981.5                        -> ratio 0.106

Nobody noticed the first one, and the round published the median, which is how
a flat scheduling offset got written up as a progressive curve across a
damage-count axis. This module is that tell, read automatically.

THE TWO ARMS, and they catch different things.

`bimodal(...)` - ONE ARM'S OWN RUNS. Fires when min/median < MIN_MEDIAN_FLOOR.
This is the section 12 symptom: the cell's ABSOLUTE times are a mixture of two
populations, so its median is not a time that the machine ever actually took.

`disagree(...)` - THE COMPARISON. Fires when the median-of-ratios and the
min/min ratio differ by more than RATIO_SPREAD_CEILING in either direction.
This one is not hypothetical either: section 5 of the same note ran an A/A
control - the team arm against ITSELF, same binary, same budget - whose MEDIAN
came out at 1.359 while its min/min read 1.001, and concluded in prose that
"a statistic that moves 36% between two identical arms is not measuring the
thing under test". That rule existed, correctly, exactly once, applied by
hand, in one section. This is it made mechanical.

They are complementary and neither subsumes the other. An A/B whose two arms
are demoted TOGETHER has two bimodal arms and a sound ratio, which is the
common case and is why the 17 Sep audit found no corrected figure; an A/B
where only one arm caught a stall has a clean-looking min/median on each arm
and a ratio that moves 36%.

WHY IT WARNS AND DOES NOT REFUSE.

These drivers are run by a person reading output on a bench box, often over
ssh, often at the tail of a round that has already cost an hour. A refusal
that a lane learns to work around is worse than a warning that a lane reads,
and a tripped cell is NOT necessarily wrong: a cold-cache arm, a first-run
effect, a deliberately hog-loaded control cell and a genuinely bimodal
workload all trip it legitimately, and the 17 Sep audit found examples of
every one of those in the banked corpus. So the output is loud, unmissable
and advisory, and the judgement stays with the reader.

Corollary, and it is the operational reason this file is small and has no
imports outside the standard library: a driver COPIED to a bench box without
it must still run. Import it the way the drivers do, which degrades to a
no-op rather than killing a round:

    try:
        sys.path.insert(0, <path to an internal note>)
        from cellguard import bimodal, disagree
    except Exception:
        def bimodal(*a, **k): return ""
        def disagree(*a, **k): return ""

WHERE THE THRESHOLDS COME FROM - measured, not chosen.

Over the whole banked corpus as of 17 Sep 2026 (5,085 timed per-arm cells,
excluding logs marked VOID and the deliberately-degraded observation logs
section 12.4 banks), the min/median distribution is:

    median 0.969   p10 0.902   p5 0.879   p1 0.770   p0.5 0.732   p0.1 0.603

so MIN_MEDIAN_FLOOR = 0.70 fires on 0.31% of everything ever banked - about
one cell in 320. The floor is NOT free to lower: 0.50 misses the 0.641 cell
that motivated the whole thing, which is the single test this threshold has to
pass. Nor is it free to raise much: 0.80 is 1.5% and 0.85 is 2.8%, and a
warning that fires on one cell in thirty-five is a warning a lane stops
reading. 0.65 would clear the motivating cell by 0.009, which is no margin at
all. There is no knee in the distribution to snap to - it is smooth - so this
is a rate decision and it is documented as one.

RE-DERIVED, and the earlier numbers are named rather than overwritten quietly.
This block read 4,926 cells and 0.49% at 0.70 until
`cell-armbench-quiet-attempt-2026-09-17.log` was renamed to carry `VOID` on
17 Sep 2026 - its author had condemned all three of its rounds in prose since
the day it was taken, and the marker only caught up with the filename. That
took its eight cells out of BOTH the numerator and the denominator. Every
figure the argument turns on fell and none crossed a line it was on the wrong
side of. If a threshold moves, re-run `--scan` and replace these, because the
RATE is the whole argument for the number.

For the second arm, the median-vs-min/min spread over the 3,149 banked ratio
cells is:

    median 1.010   p90 1.039   p95 1.056   p99 1.105   p99.5 1.156

so RATIO_SPREAD_CEILING = 1.15 fires on 0.54%, and it ranks section 5's
hand-flagged A/A cells (1.533, 1.358, 1.246, 1.213) at the top of the corpus,
which is the check reproducing a human's published judgement.

STATED LIMITS.

* **A tripped cell is a question, not a verdict.** See "why it warns" above.
* **An UNtripped cell is not a clean cell.** A box demoted for a WHOLE cell
  has every run in the slow mode, a tight min/median, and a median that is
  7x wrong. That is section 12.4's R1 d=3 cell exactly (3244.8 ms median over
  a 3076.3 min - ratio 0.948, perfectly ordinary). This catches the box
  CROSSING, never the box being in the state. The A/A control and the
  per-cell foreign-load reading remain what catch the latter, and nothing
  here replaces them.
* **It reads statistics, not causes.** Section 12's demotion inflates the
  process's own CPU alongside its wall; a thread-pool tail does not. This
  module never sees the CPU column, so it cannot tell you which you have. The
  warning says to go and look; section 12.7 says what to look at first.
* **Two runs are not a distribution.** Below MIN_RUNS the arms return nothing,
  because min/median over 3 runs is dominated by which run happened to be
  first.

CHANGING THIS FILE.

One rule, one copy: every driver that prints a min beside a median reads its
rule from here. If a new driver needs the same check, IMPORT it - do not write
a second copy with a threshold of its own, which is the failure the CLAUDE.md
gate-suite convention names. If a threshold moves, re-run
`cellguard.py --scan research` first and put the new rate in the block above,
because the rate is the whole argument for the number.

WHO READS IT is an internal roster gate, added 17 Sep 2026, and it exists
because nothing anywhere said when a driver DIDN'T. It derives the population
from what a script PRINTS - it renders each format string and asks the
`scan_line` / `scan_ratio_line` below whether the result parses - so the
roster and the scan below share one set of patterns and cannot drift. Note
the consequence in both directions: a sixth print format added here widens
that roster for free, and a format NOT here is invisible to both. "Prints a
`min/min`" is the wrong predicate and was measured to be - twelve of the
fourteen drivers it found print no such token.

USAGE AS A SCRIPT.

    cellguard.py --scan research          re-audit every banked log
    cellguard.py --scan research --floor 0.8 --verbose
    cellguard.py --selftest               the built-in cases

The `--scan` arm is what produced an internal note
and exists so the audit is repeatable rather than a one-off. It parses the
five per-arm print formats the corpus actually uses; `--scan` reports the
lines it could see and a driver family that prints its statistics some sixth
way is invisible to it, which is a real blind spot and is why the audit
quantified it rather than assuming the dominant format was all of them.
"""

import re
import sys

MIN_MEDIAN_FLOOR = 0.70
RATIO_SPREAD_CEILING = 1.15
MIN_RUNS = 6

BANNER = "  *** BIMODAL CELL - READ THIS BEFORE USING THE MEDIAN ***"


def bimodal(label, runs, floor=MIN_MEDIAN_FLOOR, min_runs=MIN_RUNS):
    """One arm's own runs. Returns a warning block, or "" if the arm is sound.

    `runs` is the arm's per-run times, any unit, unsorted.
    """
    try:
        vals = sorted(float(x) for x in runs)
    except (TypeError, ValueError):
        return ""
    if len(vals) < min_runs:
        return ""
    lo = vals[0]
    n = len(vals)
    med = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0
    if med <= 0 or lo <= 0:
        return ""
    ratio = lo / med
    if ratio >= floor:
        return ""
    return "\n".join([
        BANNER,
        "  %s: min %.4g is %.3f of the median %.4g  (span %.4g-%.4g, n=%d)"
        % (label, lo, ratio, med, lo, vals[-1], n),
        "  At least one run was far faster than most, so this cell's runs are a",
        "  MIXTURE and its median is not a time the machine actually took. The",
        "  known cause on this fleet is a box crossing into or out of an",
        "  efficiency-core confinement mid-cell (see",
        "  an internal note section 12): a",
        "  flat 7.2x to 7.5x, with the process's OWN user+sys inflated alongside",
        "  its wall - check the CPU column FIRST, that is the tell that separates",
        "  it from an ordinary foreign-load tail. A cold arm,",
        "  a first-run effect or a deliberately loaded control cell trips this",
        "  legitimately; say which in the log if you publish the cell anyway.",
    ])


def disagree(label, median_ratio, minmin_ratio, ceiling=RATIO_SPREAD_CEILING):
    """The comparison. Returns a warning block, or "" if the two agree."""
    try:
        a, b = float(median_ratio), float(minmin_ratio)
    except (TypeError, ValueError):
        return ""
    if a <= 0 or b <= 0:
        return ""
    spread = max(a / b, b / a)
    if spread < ceiling:
        return ""
    return "\n".join([
        BANNER,
        "  %s: median ratio %.3f against min/min %.3f  (they differ by %.2fx)"
        % (label, a, b, spread),
        "  The two estimators of the SAME comparison disagree. A statistic that",
        "  moves this far between two readings of one pair is not measuring the",
        "  thing under test - section 5 of",
        "  an internal note found exactly this",
        "  on an A/A control, the team arm against ITSELF reading 1.359 on the",
        "  median and 1.001 on min/min. Prefer the min/min here, and",
        "  do not publish the median ratio without saying the two disagreed.",
    ])


# ---------------------------------------------------------------- scan mode

# The five per-arm formats the banked corpus actually uses. Order matters:
# the first match on a line wins. `_SWAPPED` names the patterns whose FIRST
# group is the min rather than the median.
_PATTERNS = [
    re.compile(r"median\s+([0-9.]+)\s*(?:ms)?\s+min\s+([0-9.]+)"),
    re.compile(r"\bmed(?:ian)?=\s*([0-9.]+)\s+min=\s*([0-9.]+)"),
    re.compile(r"\bmin=\s*([0-9.]+)\s+med(?:ian)?=\s*([0-9.]+)"),
    re.compile(r"median\s+([0-9.]+)\s*ms[^()]*\(\s*min\s+([0-9.]+)"),
    re.compile(r"min=\s*([0-9.]+)\s+med=\s*([0-9.]+)"),
]
_SWAPPED = {2, 4}

# The ratio forms vary more than the per-arm ones: "median 1.359   min/min
# 1.001", "= 0.669   (min/min 0.621)" and "B/A med=0.790 min/min=0.544" are
# all in the corpus, and the last of them names no "median" at all. So this
# anchors on `min/min` and takes the number immediately before it, with only
# whitespace and brackets allowed between the two.
_RATIO = re.compile(r"([0-9.]+)[\s)(]*min/min\s*=?\s*([0-9.]+)")


def scan_line(line):
    """(median, min) off one banked log line, or None."""
    for k, pat in enumerate(_PATTERNS):
        m = pat.search(line)
        if not m:
            continue
        a, b = float(m.group(1)), float(m.group(2))
        med, lo = (b, a) if k in _SWAPPED else (a, b)
        if med <= 0 or lo <= 0 or lo > med * 1.0001:
            return None
        return med, lo
    return None


def scan_ratio_line(line):
    """(median ratio, min/min ratio) off one banked log line, or None."""
    m = _RATIO.search(line)
    if not m:
        return None
    a, b = float(m.group(1)), float(m.group(2))
    return (a, b) if a > 0 and b > 0 else None


# Logs their own author already condemned, or ran degraded ON PURPOSE. These
# are not findings and they drown the report: the VOID armbench cell alone
# contributes 60-odd hits down to a ratio of 0.074, and section 12.4's banked
# observation logs are a DELIBERATE recording of a box in the degraded state.
# The scan says how many it skipped rather than going quiet about them, per
# the "failing to find is failing" rule in CLAUDE.md's gate-suite section.
_SKIP_NAMES = {
    "nat-f5-ladder-degraded-r1.log",
    "nat-f5-ladder-degraded-r2.log",
    "nat-f7-qos-degraded.log",
    "m1-f7-qos-r1.log",
    "m1-f7-qos-r2.log",
}
_SKIP_MARKS = ("VOID", "contaminated", "degraded")


def _skipped(path):
    name = path.name
    return name in _SKIP_NAMES or any(m in name for m in _SKIP_MARKS)


def _scan(root, floor, ceiling, verbose, include_all=False):
    import pathlib

    root = pathlib.Path(root)
    cells = ratios = skipped = 0
    hits = []
    for p in sorted(root.rglob("*.log")):
        if not include_all and _skipped(p):
            skipped += 1
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            got = scan_line(line)
            if got:
                cells += 1
                med, lo = got
                if lo / med < floor:
                    hits.append(("bimodal", p, i, lo / med, line.strip()))
                continue
            got = scan_ratio_line(line)
            if got:
                ratios += 1
                a, b = got
                spread = max(a / b, b / a)
                if spread >= ceiling:
                    hits.append(("disagree", p, i, spread, line.strip()))
    print("cellguard: %d per-arm cells and %d ratio cells over %s"
          % (cells, ratios, root))
    if skipped:
        print("cellguard: skipped %d log(s) already marked VOID/contaminated or "
              "banked as deliberate degraded observations (--all to include)"
              % skipped)
    print("cellguard: floor %.2f, ceiling %.2f -> %d flagged (%.2f%% of cells)"
          % (floor, ceiling, len(hits), 100.0 * len(hits) / max(cells + ratios, 1)))
    for kind, p, i, val, line in sorted(hits, key=lambda h: (h[0], h[3])):
        print("  %-8s %.3f  %s:%d" % (kind, val, p, i))
        if verbose:
            print("           %s" % line[:120])
    return 0


def _selftest():
    fails = []

    def ck(name, got, want):
        if bool(got) != want:
            fails.append("%s: expected %s, got %r" % (name, want, got[:60]))

    # The motivating cell: min 489.6 under median 764.1. It MUST fire - this is
    # the single case the floor exists to catch, and 0.50 would miss it.
    ck("motivating 0.641", bimodal("d5", [489.6] + [764.1] * 20), True)
    # An ordinary tight cell.
    ck("tight", bimodal("d1", [171.4, 173.5, 174.0, 172.8, 175.1, 173.9]), False)
    # A box demoted for the WHOLE cell is tight and NOT caught - the documented
    # blind spot, pinned so nobody reads a clean report as a clean box.
    ck("wholly demoted", bimodal("d3", [3076.3, 3244.8, 3300.0, 3244.8, 3400.0, 3920.2]), False)
    # Too few runs to have a distribution.
    ck("short", bimodal("x", [10.0, 100.0, 100.0]), False)
    ck("empty", bimodal("x", []), False)
    ck("junk", bimodal("x", ["a", "b"]), False)
    # Section 5's A/A: median 1.359 against min/min 1.001.
    ck("A/A 1.359", disagree("aa", 1.359, 1.001), True)
    ck("agreeing", disagree("r", 0.921, 0.868), False)
    ck("junk ratio", disagree("r", 0, 1), False)

    # The five banked print formats the scan arm must read.
    cases = [
        ("  base   median  764.115 ms   min  489.604   span 489.6-5375.3", 764.115, 489.604),
        ("v16m n=20/arm  A(reopen) med=1052.68 min=691.54  B med=832.10", 1052.68, 691.54),
        ("ENGINE warm n=7 min=608.22 median=668.16 max=669.23", 668.16, 608.22),
        ("COLD reopen  median    6.16 ms   3.29 GB/s  (min 4.21 max 8.60 n=7)", 6.16, 4.21),
        ("c1024-serial     n= 24 wall min=   174.6 med=   177.8", 177.8, 174.6),
    ]
    for line, wmed, wmin in cases:
        got = scan_line(line)
        if not got or abs(got[0] - wmed) > 1e-6 or abs(got[1] - wmin) > 1e-6:
            fails.append("scan_line %r -> %r, wanted (%s, %s)" % (line[:40], got, wmed, wmin))
    for line, wa, wb in [
        ("  new/base  median 1.359   min/min 1.001", 1.359, 1.001),
        ("SOURCE A/B  warm onehandle/reopen = 0.669   (min/min 0.621)", 0.669, 0.621),
        ("S-c142-1-r5 new/old median 1.063  min/min 0.991", 1.063, 0.991),
        ("B/A med=0.790 min/min=0.544", 0.790, 0.544),
    ]:
        got = scan_ratio_line(line)
        if not got or abs(got[0] - wa) > 1e-6 or abs(got[1] - wb) > 1e-6:
            fails.append("scan_ratio_line %r -> %r, wanted (%s, %s)" % (line[:40], got, wa, wb))

    for f in fails:
        print("FAIL  %s" % f)
    print("cellguard selftest: %s" % ("FAILED (%d)" % len(fails) if fails else "ok"))
    return 1 if fails else 0


def main(argv):
    import argparse

    ap = argparse.ArgumentParser(description="the bimodal-cell rule, shared")
    ap.add_argument("--scan", metavar="DIR", help="re-audit every *.log under DIR")
    ap.add_argument("--floor", type=float, default=MIN_MEDIAN_FLOOR)
    ap.add_argument("--ceiling", type=float, default=RATIO_SPREAD_CEILING)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="include logs marked VOID/contaminated/degraded")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return _selftest()
    if a.scan:
        return _scan(a.scan, a.floor, a.ceiling, a.verbose, a.all)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
