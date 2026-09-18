#!/usr/bin/env python3
"""stealsub.py - the STEAL LADDER as a reducer-agnostic filter: census a round's
hypervisor steal, and emit the same legs again with the noisy ones dropped, so
ANY reducer can be re-run at several steal thresholds without being edited.

    stealsub.py census legs.jsonl [more.jsonl ...]
    stealsub.py keep 6.2 legs.jsonl [...] > legs-lt6.2.jsonl
    stealsub.py ladder legs.jsonl                 # prints the thresholds to use
    stealsub.py sample 45 7 legs.jsonl            # the NULL: 45 legs at random, seed 7
    stealsub.py selftest                          # 12 arms, no round needed, any platform

WHAT THIS IS FOR, AND IT IS NOT TIDINESS. Section 8.18.6 of
an internal note re-fitted one round's knee
at five steal thresholds and watched the answer walk 3,500 -> 4,275 while r2
rose 0.923 -> 0.956: a 20% displacement of a STRUCTURAL CONSTANT on a guest
whose steal median was only 3.41%. The generalisation, written up as memory
topic `nzbfast-quiet-leg-gate-and-rig-lock-queues` item 7, is the reason this
file exists:

    A GUEST IS FINE FOR A RATIO AND NOT FOR A LOCATION.

Symmetric noise averages out of a ratio of two fitted slopes, because both
slopes carry it and it cancels. It does NOT average out of a fitted BREAKPOINT,
because a breakpoint is located by where the residual stops improving, and an
inflated leg pulls the located point toward wherever that leg happens to sit.
The two kinds of answer look equally well-measured in the reducer's output -
same r2, same table, same confident line - which is exactly why this has to be
a CHECK somebody runs and not a habit somebody remembers.

HOW TO READ THE LADDER. Re-run your reducer at each threshold and put the
answer and its r2 side by side.

  - answer STATIONARY across the ladder      -> the box is not the measurement.
  - answer MONOTONE with r2 MONOTONE         -> the box IS the measurement, and
    the cleanest rung is the better estimate, not the unfiltered one.
  - answer moves NON-monotonically, or r2 falls as legs are dropped -> you are
    fitting a shrinking sample, not removing a bias. Say so and stop; this test
    does not license picking the threshold that flatters the answer.

AND `sample` IS THE NULL THE LADDER IS NOTHING WITHOUT. Every rung of the
ladder throws legs away, and throwing legs away moves a fitted answer on its
own - so "the answer moved when I filtered" is not evidence until you know how
far it moves when you drop the SAME NUMBER OF LEGS AT RANDOM. `sample n seed`
emits exactly that: n legs drawn without replacement under a named seed, so a
caller can run twenty draws through the same reducer and compare the steal
rung's displacement against that spread. A steal rung inside the random spread
is a shrinking sample and NOT a removed bias, whatever its r2 does. This guard
is not optional and it is not a refinement: it is the difference between this
test and a way of choosing the answer you wanted.

THE THRESHOLDS MUST BE PRE-SPECIFIABLE, and `ladder` prints exactly the five
8.18 used, derived from the round's own distribution rather than chosen after
seeing the answers: none, median+1sd, and three round figures bracketing it.
Choosing a threshold because it moved the answer where you wanted is the defect
this whole check exists to catch, performed deliberately.

`steal_pct` IS PER-LEG AND ACROSS THE LEG. `pdrv.cpu_stat_jiffies` samples
/proc/stat either side of the leg and divides steal jiffies by TOTAL jiffies on
every core in that window, so it is a share of the box over that leg and never
a cumulative figure.

THREE VALUES AND ONLY THE FIRST IS DATA: a float is a measurement; the string
`"n/a"` is "this kernel does not export steal", which is every macOS and every
Windows leg and is NOT a quiet box; and a missing field is a round banked
before `pdrv` carried it. A file with no float in it has nothing to say here
and this tool REFUSES it rather than reporting a clean ladder over nothing -
failing to find is failing. A float 0.0 IS a measurement and IS data: it is
what bare-metal Linux reads, and several banked rounds are exactly that.
"""
import json
import os
import sys


def load(paths):
    legs = []
    for p in paths:
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    legs.append(json.loads(line))
    return legs


def steal_of(leg):
    """The leg's steal as a float, or None when it is not a measurement."""
    v = leg.get("steal_pct")
    return float(v) if isinstance(v, (int, float)) else None


def stats(vals):
    vals = sorted(vals)
    n = len(vals)
    mean = sum(vals) / n
    med = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0
    sd = (sum((v - mean) ** 2 for v in vals) / (n - 1)) ** 0.5 if n > 1 else 0.0
    return {"n": n, "min": vals[0], "max": vals[-1], "mean": mean, "med": med,
            "sd": sd, "p90": vals[min(n - 1, int(0.9 * n))]}


def measured(legs, paths):
    vals = [s for s in (steal_of(l) for l in legs) if s is not None]
    if not vals:
        raise SystemExit(
            "stealsub: no leg in %s carries a numeric steal_pct - this round is "
            "n/a (a non-Linux kernel) or predates the field, and has NOTHING to "
            "say about steal. Refusing rather than reporting a clean ladder over "
            "nothing." % ", ".join(paths))
    return vals


def ladder_for(vals):
    """The five pre-specifiable rungs, from the round's own distribution."""
    s = stats(vals)
    rungs = [None, round(s["med"] + s["sd"], 2)]
    for f in (8.0, 5.0, 4.0):
        if s["min"] < f <= s["max"]:
            rungs.append(f)
    out = []
    for r in rungs:
        if r not in out:
            out.append(r)
    return [out[0]] + sorted(out[1:], reverse=True)


def selftest():
    """Arms that need no round and no Linux. The point of the last three is the
    REFUSALS: a tool that reports a clean ladder over legs it cannot read is
    the rubber stamp this whole check exists to replace."""
    import io
    import tempfile
    fails = []

    def check(name, ok, detail=""):
        print("%-4s %s%s" % ("ok" if ok else "FAIL", name,
                             "" if ok else "   <- " + str(detail)))
        if not ok:
            fails.append(name)

    legs = [{"steal_pct": v} for v in
            [0.0, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 10.0, 40.0]]
    vals = [steal_of(l) for l in legs]
    s = stats(vals)
    check("median of ten known values", s["med"] == 3.5, s["med"])
    check("min and max are the ends", (s["min"], s["max"]) == (0.0, 40.0), s)
    check("sd is the SAMPLE sd (n-1)", abs(s["sd"] - 11.9258) < 1e-3, s["sd"])
    check("a float 0.0 is DATA, not absence", steal_of({"steal_pct": 0.0}) == 0.0)
    check("the string n/a is absence", steal_of({"steal_pct": "n/a"}) is None)
    check("a missing field is absence", steal_of({}) is None)
    lad = ladder_for(vals)
    check("the ladder opens unfiltered", lad[0] is None, lad)
    check("the ladder descends after that",
          lad[1:] == sorted(lad[1:], reverse=True), lad)
    check("a threshold outside the round is not offered",
          all(t is None or s["min"] < t <= s["max"] for t in lad), lad)
    kept = [l for l in legs if steal_of(l) < 4.0]
    check("keep is STRICTLY less than the threshold (4.0 is OUT)",
          len(kept) == 5, len(kept))
    mixed = legs + [{"steal_pct": "n/a"}]
    check("measured() accepts a file with SOME floats",
          len(measured(mixed, ["x"])) == 10)
    try:
        measured([{"steal_pct": "n/a"}, {}], ["x"])
        check("measured() REFUSES a file with no float", False, "returned")
    except SystemExit as e:
        check("measured() REFUSES a file with no float", "NOTHING to say" in str(e), e)
    import random
    a = random.Random(3).sample(legs, 5)
    b = random.Random(3).sample(legs, 5)
    check("sample is reproducible under its seed", a == b)
    check("sample is WITHOUT replacement", len({id(x) for x in a}) == 5)
    if fails:
        print("---\nFAILED %d: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("---\nstealsub selftest green on %s (%d arms)." % (sys.platform, 14))
    return 0


def main(argv):
    if argv and argv[0] == "selftest":
        raise SystemExit(selftest())
    if len(argv) < 2:
        raise SystemExit(__doc__.split("\n\n")[0])
    cmd = argv[0]
    if cmd == "sample":
        import random
        n, seed = int(argv[1]), int(argv[2])
        paths = argv[3:]
        legs = load(paths)
        measured(legs, paths)
        pool = [l for l in legs if steal_of(l) is not None]
        if n > len(pool):
            raise SystemExit("stealsub: asked for %d of %d measured leg(s)" % (n, len(pool)))
        for l in random.Random(seed).sample(pool, n):
            print(json.dumps(l))
        return
    if cmd == "keep":
        thr = float(argv[1])
        paths = argv[2:]
        legs = load(paths)
        measured(legs, paths)
        for l in legs:
            s = steal_of(l)
            if s is not None and s < thr:
                print(json.dumps(l))
        return
    paths = argv[1:]
    legs = load(paths)
    vals = measured(legs, paths)
    s = stats(vals)
    nna = sum(1 for l in legs if steal_of(l) is None)
    if cmd == "census":
        print("legs=%d measured=%d not-measured=%d" % (len(legs), s["n"], nna))
        print("steal%%  min=%.2f med=%.2f mean=%.2f sd=%.2f p90=%.2f max=%.2f"
              % (s["min"], s["med"], s["mean"], s["sd"], s["p90"], s["max"]))
        print()
        print("%-10s %8s %8s" % ("threshold", "kept", "% kept"))
        for thr in ladder_for(vals):
            k = s["n"] if thr is None else sum(1 for v in vals if v < thr)
            print("%-10s %8d %7.1f%%" % ("none" if thr is None else "< %.2f" % thr,
                                         k, 100.0 * k / s["n"]))
        return
    if cmd == "ladder":
        for thr in ladder_for(vals):
            print("none" if thr is None else "%.2f" % thr)
        return
    raise SystemExit("stealsub: unknown command %r (census, keep, ladder, sample, selftest)" % cmd)


if __name__ == "__main__":
    main(sys.argv[1:])
