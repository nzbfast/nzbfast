#!/usr/bin/env python3
"""cfpowersum.py - the THERMAL AND FREQUENCY half of a sitting, in time order.

    cfpowersum.py LABEL=LOG[,LOG...] [LABEL=LOG...]

WHY IT EXISTS. The within-sitting drift census of 18 Sep 2026 ranked three
candidates for the `c_f` drift it measured and could rank only two of them
against evidence. The third - THERMAL OR POWER DRIFT ACROSS A SITTING - was
untestable by construction rather than merely unproven: no LEG line in the
whole banked corpus carried a frequency or a temperature, so there was nothing
to reduce. `wcomb.ps1` records them from 18 Sep 2026 onward. This reads them.

IT ANSWERS ONE QUESTION AND NOT THE INTERESTING ONE. It says whether the part
clocked down or heated up across a sitting; it does NOT say whether that is
what moved `c_f`. Pair it with `cfdriftsum.py` over the same logs and read the
two tables together: a sitting whose `c_f` rose monotonically WITHOUT a
frequency fall has ruled candidate 3 out, and one where both moved together has
a correlation and still not a mechanism. Reporting the pairing as a cause is
the error this file exists to make checkable rather than to commit.

TIME ORDER IS THE POINT, so units print in the order of their first leg's
timestamp rather than the order given. Drift is time-ordered - that is the
census's own finding about the two-binary sitting, which rose monotonically
through 40 minutes - and a table sorted any other way hides exactly the shape
being looked for.

ABSENT IS NOT ZERO. A log written before 18 Sep 2026 carries none of these
fields, and a reducer that averaged a missing frequency as 0 would report a
catastrophic clock drop that never happened. A unit with no readings SAYS so
and prints nothing else; a unit with some prints the count it actually had.
This is the pattern `wcombsum.shape()` uses for `slice=`/`n=`, stated in the
output rather than left to the reader.

THE FREQUENCY COLUMNS ARE NOT READABLE TODAY AND THIS FILE PRINTS THEM ANYWAY.
Established 18 Sep 2026 by lane `cf-thermal-drift-candidate3-18sep`, from the
six validation legs `e7f7cd14d`'s own lane banked and nothing else:
`perf_pct`, `freq_mhz` and their `_after` twins come from a SINGLE
un-refreshed CIM query of a DELTA counter, and across six legs that each held
~10 of 12 threads busy on a box whose thermometer read 27.9 C on every sample,
the end-of-leg frequency spans 912-2585 MHz. That is 2.83x with everything
that could move it held fixed, and the level is wrong too: the route
an internal note section 2a proved reads the same
idle box at 109.74-110.45% of nominal where this one reads 24-30%.

SO DO NOT QUOTE THE FREQUENCY HALF OF THIS TABLE, and in particular do not
quote the "frequency X -> Y MHz" line this file prints across a sitting: it is
the sentence candidate 3 would be answered with, and its inputs have a 2.83x
spread and no physical meaning. The temperature half and `throttle_pct` are
SOUND - both are instantaneous gauges, correctly read by a single query - so a
sitting can still be asked whether it HEATED, which is the cheap stand-down
the candidate-3 design puts first. The diagnosis, the proposed raw-delta fix
and its on-box validator are in
`rounds/cf-thermal-drift-2026-09-18/`. The columns are left in place,
and the warning added beside them rather than the computation deleted, because
the arithmetic becomes correct the moment the sampler is fixed and a column
that silently vanishes is how a gap stops being visible - the same reason
`pkg_w` is printed.

`throttle_pct` READS 100 WHEN NOTHING IS THROTTLING. It is
`PercentPassiveLimit`, a ceiling and not a load, so 100 is a clean bill of
health and a DROP below 100 is the passive-throttle signal. Worth stating once
because the polarity reads backwards at a glance.

`pkg_w` IS EXPECTED TO READ `na` ON THIS FLEET. Windows does not surface Intel
RAPL to user mode and no box here carries a hardware-monitor driver, so the
column is a record of what could not be measured. It is printed anyway,
because a column that silently vanishes is how a gap stops being visible.

THIS IS A REPORT AND MUST NOT BECOME A GATE. There is no pass condition: a hot
box is a fact about a night, not a defect, and a threshold would either red
every summer sitting or say nothing. It is not in `tools/preflight.py`'s roster
and must not be added to it - the same rule `cfloadsum.py` and `cfdriftsum.py`
carry, for the same reason.
"""
import statistics
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import wcombsum  # noqa: E402

# Printed as (heading, the LEG field it comes from). `perf_pct` travels beside
# the derived MHz on purpose: the MHz is nominal x perf_pct/100 and a reader who
# cannot see the input cannot check the derivation.
COLS = (("freq MHz", "freq_mhz"), ("freq after", "freq_after_mhz"),
        ("perf %", "perf_pct"), ("temp C", "temp_c"),
        ("temp after", "temp_after_c"), ("throttle %", "throttle_pct"))


def nums(rows, field):
    """Every parseable reading of `field`, skipping absent and empty ones.

    Empty is what the harness writes when a counter class was momentarily
    unavailable, which is a real state and not a zero.
    """
    out = []
    for r in rows:
        v = (r.get(field) or "").strip()
        if not v:
            continue
        try:
            out.append(float(v))
        except ValueError:
            continue
    return out


def unit(label, paths):
    rows = wcombsum.legs(paths)
    ts = sorted(r["ts"] for r in rows if r.get("ts"))
    pkg = sorted({(r.get("pkg_w") or "").strip() for r in rows} - {""})
    return {"label": label, "rows": rows, "n": len(rows),
            "t0": ts[0] if ts else "", "t1": ts[-1] if ts else "",
            "pkg": ",".join(pkg) if pkg else "(absent)"}


def report(units):
    units.sort(key=lambda u: u["t0"])
    print("# units in TIME ORDER of their first leg, which is the order drift "
          "would show in")
    print()
    print("| unit | legs | first leg | last leg | "
          + " | ".join("%s med (min-max)" % h for h, _ in COLS) + " | pkg_w |")
    print("|---|---:|---|---|" + "".join("---:|" for _ in COLS) + "---|")
    silent = []
    for u in units:
        cells = []
        got = 0
        for _h, f in COLS:
            v = nums(u["rows"], f)
            if not v:
                cells.append("-")
                continue
            got += 1
            cells.append("%.0f (%.0f-%.0f)" % (statistics.median(v), min(v), max(v))
                         if max(v) - min(v) >= 1 else "%.1f" % statistics.median(v))
        if not got:
            silent.append(u["label"])
        print("| %s | %d | %s | %s | %s | %s |"
              % (u["label"], u["n"], u["t0"][11:19], u["t1"][11:19],
                 " | ".join(cells), u["pkg"]))
    print()
    if silent:
        print("# NO FREQUENCY OR THERMAL FIELD ON: %s" % ", ".join(silent))
        print("# Those logs predate wcomb.ps1's 18 Sep 2026 power fields. That is")
        print("# ABSENT, NOT ZERO and NOT a quiet box - they say nothing either way")
        print("# about candidate 3, and a row of dashes is the whole of what they")
        print("# can support.")
        print()
    span = [u for u in units if nums(u["rows"], "freq_mhz")]
    if len(span) >= 2:
        f0 = statistics.median(nums(span[0]["rows"], "freq_mhz"))
        f1 = statistics.median(nums(span[-1]["rows"], "freq_mhz"))
        t0 = nums(span[0]["rows"], "temp_c")
        t1 = nums(span[-1]["rows"], "temp_c")
        print("# ACROSS THE SITTING, first unit carrying the fields to last:")
        # NOT A FINDING, and labelled in the output rather than only in this
        # file's header, because a table travels and a docstring does not.
        print("#   frequency %.0f -> %.0f MHz (%+.1f%%)  <- UNREADABLE, see below"
              % (f0, f1, 100.0 * (f1 / f0 - 1.0)))
        if t0 and t1:
            print("#   temperature %.1f -> %.1f C (%+.1f)"
                  % (statistics.median(t0), statistics.median(t1),
                     statistics.median(t1) - statistics.median(t0)))
        print("# A c_f drift WITHOUT a frequency fall rules candidate 3 out for this")
        print("# sitting; the two moving together is a correlation and not yet a")
        print("# mechanism. Read this beside cfdriftsum.py over the same logs.")
        print("# BUT NOT YET: the frequency line above is a single un-refreshed")
        print("# query of a DELTA counter and spans 2.83x on legs that differed in")
        print("# nothing - rounds/cf-thermal-drift-2026-09-18/README.md.")
        print("# The TEMPERATURE line is sound and may be read. Neither candidate 3")
        print("# nor its refutation can be argued from the frequency half today.")
    print()
    print("# REPORT, not a gate. pkg_w reads `na` wherever Windows cannot surface")
    print("# Intel RAPL, which is every box on this fleet - see wcomb.ps1's header.")


def main(argv):
    if not argv:
        sys.exit(__doc__)
    units = []
    for a in argv:
        label, _, paths = a.partition("=")
        if not paths:
            sys.exit("REFUSED: %r is not LABEL=LOG[,LOG...]" % a)
        units.append(unit(label, paths.split(",")))
    report(units)


if __name__ == "__main__":
    main(sys.argv[1:])
