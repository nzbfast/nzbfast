#!/usr/bin/env python3
"""p4recheck.py - re-reduce 8.16.5's 4 MiB ladder from its own banked legs and
diff EVERY column of its published table, not just the one column 8.20.8 read.

WHY THIS IS A SCRIPT AND NOT A HAND SUM. 8.16.11's provenance says 8.16.5's
per-cell reduction "was scratch and is described in 8.16.5 rather than
committed", so there is no committed reducer to re-run: the reduction has to
be re-derived from the section's own prose. That makes this cell the one
member of the census whose re-run is a RE-IMPLEMENTATION, and the prose is
explicit enough to pin it - "7 rungs, 28 legs", four legs a rung, and
8.20.8 already established that four of the seven `ntt syndromes` rows are
exact medians of the four banked legs. So median-of-four is the reduction,
and this script applies it to wall, cpu, peak_mb and syn_total alike.

8.20.8 checked `ntt syndromes` ALONE and found three rows unreproducible. The
other three numeric columns of that table (wall s, cpu s, peak MB) were never
checked by anybody, and a table with three bad cells in one column is exactly
the table whose other columns are worth reading.

`--selftest` re-derives 8.20.8's own published finding: it requires w4, w6,
w8 and w9 to be exact medians of the four banked legs and w5, w7 and w10 not
to be, and requires w5 and w10 to sit BELOW every one of their four legs.
A census that cannot reproduce the finding that motivated it is not a census.
"""
import json, os, statistics, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ROUND = os.path.join(ROOT, "research", "parfast-ntt-block-size-2026-09-17")
LEG_FILES = ("legs-p4.jsonl", "legs-p4b.jsonl")
LEGS = [os.path.join(ROUND, f) for f in LEG_FILES]
BANK = os.path.join(HERE, "legs.json")
FIELDS = ("rung", "ok", "path", "wall", "cpu", "syn_total", "peak_mb")

# 8.16.5's published table, transcribed from
# an internal note. rung -> (wall, cpu, syn, peak)
PUBLISHED = {
    "w4":  (278.60, 2152.3, 155.81, 11224),
    "w5":  (309.62, 2429.3, 188.30, 11224),
    "w6":  (339.14, 2660.3, 219.53, 11224),
    "w7":  (368.34, 2899.1, 245.13, 11224),
    "w8":  (392.93, 3082.1, 272.14, 11224),
    "w9":  (393.36, 3100.8, 275.78, 11223),
    "w10": (414.61, 3267.5, 281.44, 11224),
}
ORDER = ["w4", "w5", "w6", "w7", "w8", "w9", "w10"]
COLS = [("wall", "wall", 2), ("cpu", "cpu", 1), ("syn", "syn_total", 2), ("peak", "peak_mb", 0)]


def raw_legs():
    """The 28 legs of 8.16.5's 4 MiB ladder, from the round or from the bank.

    READS THE BANK WHEN THE ROUND DIRECTORY IS NOT THERE, and that is the whole
    reason the bank exists - the same construction `fitnull.py` uses one round
    over, for the same cause. 8.16.5's legs live in
    an internal note/`, which is NOT under
    `rounds/`, and `export_parfast_evidence.py`'s `SOURCES` mirrors
    only `rounds`, `fastmode-rounds-2026-09-12` and `harness` - so it copies
    THIS file into `website/parfast-bench/rounds/table-reproduction-2026-09-18/`
    and copies its inputs nowhere. A mirrored script with no inputs is a program
    nobody can run, and `selftest-roster` requires BOTH copies to be wired, so
    "skip when the legs are absent" would be a green line over nothing.

    `legs.json` is therefore banked beside this file, carrying FIELDS and
    nothing else, which is all this reduction consumes. When the round
    directory IS present the round is read and the bank is checked against it
    leg for leg, so the mirror cannot drift away from the legs it stands in for.
    """
    if all(os.path.exists(p) for p in LEGS):
        out = {}
        for name, path in zip(LEG_FILES, LEGS):
            arr = []
            for line in open(path):
                line = line.strip()
                if line:
                    arr.append(json.loads(line))
            arr = [{k: r[k] for k in FIELDS} for r in arr]
            out[name] = arr
        return out, "the round directory %s" % ROUND
    if not os.path.exists(BANK):
        sys.exit("REFUSED: neither the round directory (%s) nor the bank (%s) "
                 "is present, so there is nothing to reduce - failing to find "
                 "is failing" % (ROUND, BANK))
    return json.load(open(BANK)), "the bank %s" % BANK


def load():
    raw, src = raw_legs()
    by = {}
    for name in LEG_FILES:
        if name not in raw:
            sys.exit("REFUSED: %s carries no %s" % (src, name))
        for r in raw[name]:
            if not r.get("ok") or r.get("path") != "ntt":
                continue
            by.setdefault(r["rung"], []).append(r)
    if not by:
        sys.exit("REFUSED: no usable legs in " + src)
    return by


def med(vals):
    return statistics.median(vals)


def report(by):
    print("8.16.5's 4 MiB ladder, re-reduced from an internal note/")
    print("legs: " + ", ".join("%s=%d" % (r, len(by.get(r, []))) for r in ORDER))
    print()
    hdr = "%-5s %-5s %10s %10s %8s  %s" % ("rung", "col", "published", "re-run", "delta%", "position among the 4 legs")
    print(hdr)
    print("-" * len(hdr))
    bad = []
    for rung in ORDER:
        legs = by.get(rung)
        if not legs:
            print("%-5s  REFUSED: rung absent from the banked legs" % rung)
            bad.append((rung, "*", None))
            continue
        for i, (name, field, dp) in enumerate(COLS):
            vals = sorted(l[field] for l in legs)
            m = med(vals)
            pub = PUBLISHED[rung][i]
            delta = 100.0 * (pub - m) / m if m else float("nan")
            # Compare at the published column's own precision. `peak_mb` is
            # banked as a float and PUBLISHED as whole MB, so a raw `<` against
            # the leg minimum calls 11224 "above every leg" when every leg is
            # 11223.5-11224.0 and the median rounds to exactly 11224. Rounding
            # both sides to `dp` first is what keeps this census from reporting
            # its own formatting as a mismatch - over-reporting is the same
            # defect as skipping a cell, one axis over.
            q = lambda v: round(v, dp)
            if q(pub) == q(m):
                where = "= median"
            elif pub < vals[0]:
                where = "BELOW every leg (min %.*f)" % (dp, vals[0])
            elif pub > vals[-1]:
                where = "ABOVE every leg (max %.*f)" % (dp, vals[-1])
            else:
                where = "inside the spread, not the median [%.*f .. %.*f]" % (dp, vals[0], dp, vals[-1])
            flag = "" if where == "= median" else "   <-- not the median"
            print("%-5s %-5s %10.*f %10.*f %+8.2f  %s%s"
                  % (rung, name, dp, pub, dp, m, delta, where, flag))
            if where != "= median":
                bad.append((rung, name, delta))
        print()
    print("rows that are NOT an exact median of their own banked legs: %d of %d"
          % (len(bad), len(ORDER) * len(COLS)))
    for rung, name, delta in bad:
        print("  %-5s %-5s %s" % (rung, name, "%+.2f%%" % delta if delta is not None else "absent"))
    return bad


def selftest(by):
    ok = []

    def check(cond, msg):
        if not cond:
            sys.exit("SELFTEST FAILED: " + msg)
        ok.append(msg)
        print("ok   " + msg)

    for rung in ORDER:
        check(len(by.get(rung, [])) == 4,
              "%s carries exactly four banked legs" % rung)

    syn = {r: sorted(l["syn_total"] for l in by[r]) for r in ORDER}
    for rung in ("w4", "w6", "w8", "w9"):
        pub = PUBLISHED[rung][2]
        check(abs(med(syn[rung]) - pub) < 0.005,
              "8.20.8's four exact rows hold: %s syndromes %.2f IS the median of its legs" % (rung, pub))
    for rung in ("w5", "w7", "w10"):
        pub = PUBLISHED[rung][2]
        check(abs(med(syn[rung]) - pub) >= 0.005,
              "8.20.8's three bad rows hold: %s syndromes %.2f is NOT the median (banked %.2f)"
              % (rung, pub, med(syn[rung])))
    for rung in ("w5", "w10"):
        pub = PUBLISHED[rung][2]
        check(pub < syn[rung][0],
              "8.20.8's stronger claim holds: %s syndromes %.2f sits BELOW every one of its four legs (cheapest %.2f)"
              % (rung, pub, syn[rung][0]))
    check(PUBLISHED["w7"][2] > syn["w7"][0],
          "w7 is 'near the min' rather than below it, as 8.20.8 says (%.2f vs min %.2f)"
          % (PUBLISHED["w7"][2], syn["w7"][0]))

    # The bank against the round, so the published mirror cannot drift away
    # from the legs it stands in for. When the round is absent this IS the
    # mirror, and every check above was therefore a check ON the bank.
    if all(os.path.exists(p) for p in LEGS) and os.path.exists(BANK):
        fresh, _ = raw_legs()
        banked = json.load(open(BANK))
        check(sorted(fresh) == sorted(banked),
              "legs.json names the same two leg files as the round")
        for name in LEG_FILES:
            check(len(fresh[name]) == len(banked[name]),
                  "legs.json carries all %d legs of %s" % (len(fresh[name]), name))
            check(all(a == b for a, b in zip(fresh[name], banked[name])),
                  "legs.json agrees with %s field for field, so the published "
                  "mirror reduces the same numbers this copy does" % name)
    elif os.path.exists(BANK):
        ok.append("the round directory is absent, so this is the published "
                  "mirror reducing legs.json - every figure above is therefore "
                  "a check ON the bank")
        print("ok   " + ok[-1])
    print("---")
    print("p4recheck --selftest: OK - %d checks, 8.20.8's finding re-derived independently" % len(ok))


# ---------------------------------------------------------------- derived --

# 8.16.5 publishes THREE derived columns on top of the raw table, and all three
# are functions of `ntt syndromes` alone, which is the one column that does not
# reproduce. 8.20.8 worked out what the intercept and the w9 departure become
# and stopped there; these are the rest of the same arithmetic.
#
# sources a window, from the published table (the split is structural and
# reproduces - 8.16.5's own prose checks it against 8.11 rung by rung).
SRC = {"w4": 954, "w5": 740, "w6": 634, "w7": 529, "w8": 474, "w9": 412, "w10": 404}
K = {"w4": 4, "w5": 5, "w6": 6, "w7": 7, "w8": 8, "w9": 9, "w10": 9}
# 8.16.5's published marginal column ("s per added window") and its k<=3-line
# departure column.
PUB_MARGINAL = {"w5": 32.49, "w6": 31.24, "w7": 25.60, "w8": 27.01, "w9": 3.64}
PUB_DEPARTURE = {"w4": -0.1, "w5": +0.2, "w6": -0.1, "w7": -2.6, "w8": -4.0,
                 "w9": -12.5, "w10": -10.7}
PUB_CHARGE = {"w4": 31.692, "w5": 31.880, "w6": 31.800, "w7": 31.099,
              "w8": 31.220, "w9": 27.569, "w10": 28.536}
PUB_FIT = (31.863, 28.569)   # `ntt syndromes` = 31.863 * k + 28.569 s


def fit_three_widest(syn):
    """8.16.5 fits its line 'on the three widest rungs' - w4, w5, w6."""
    xs = [K[r] for r in ("w4", "w5", "w6")]
    ys = [syn[r] for r in ("w4", "w5", "w6")]
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    return b, a


def derived(by):
    syn = {r: med([l["syn_total"] for l in by[r]]) for r in ORDER}
    b, a = fit_three_widest(syn)
    pb, pa = PUB_FIT
    print()
    print("DERIVED COLUMNS - every one of the three is a function of `ntt syndromes` alone")
    print()
    print("the k<=3 line, fitted on the three widest rungs (w4, w5, w6):")
    print("  published   %.3f * k + %.3f" % (pb, pa))
    print("  re-run      %.3f * k + %.3f   (slope %+.2f%%, intercept %+.2f%%)"
          % (b, a, 100 * (b - pb) / pb, 100 * (a - pa) / pa))
    print("  8.20.8 predicted 31.862 * k + 29.669 from the same legs: %s"
          % ("CONFIRMED" if abs(b - 31.862) < 0.002 and abs(a - 29.669) < 0.002 else "DOES NOT MATCH"))
    print()
    hdr = "%-5s %12s %10s %10s | %12s %10s %10s | %10s %10s" % (
        "rung", "marginal pub", "re-run", "moves", "departure pub", "re-run", "moves",
        "charge pub", "re-run")
    print(hdr)
    print("-" * len(hdr))
    prev = None
    for rung in ORDER:
        line = "%-5s " % rung
        if rung in PUB_MARGINAL and prev is not None:
            mg = (syn[rung] - syn[prev]) / (K[rung] - K[prev]) if K[rung] != K[prev] else float("nan")
            line += "%12.2f %10.2f %10s | " % (PUB_MARGINAL[rung], mg,
                                               "%+.2f" % (mg - PUB_MARGINAL[rung]))
        else:
            line += "%12s %10s %10s | " % ("-", "-", "-")
        dep = 100.0 * (syn[rung] - (b * K[rung] + a)) / (b * K[rung] + a)
        line += "%12.1f%% %9.1f%% %10s | " % (PUB_DEPARTURE[rung], dep,
                                              "%+.1f" % (dep - PUB_DEPARTURE[rung]))
        line += "%10.3f %10.3f" % (PUB_CHARGE[rung], (syn[rung] - a) / K[rung])
        print(line)
        prev = rung
    print()
    print("8.16.5's flat band: its table reads the w4/w5/w7 departures as "
          "-0.1%, +0.2%, -2.6%")
    for rung in ("w4", "w5", "w7"):
        dep = 100.0 * (syn[rung] - (b * K[rung] + a)) / (b * K[rung] + a)
        print("  %-4s published %+.1f%%   on its own legs %+.1f%%" % (rung, PUB_DEPARTURE[rung], dep))
    print("  8.20.8 predicted -0.8%, +1.4%, -0.8% for that band")


if __name__ == "__main__":
    by = load()
    if "--selftest" in sys.argv[1:]:
        selftest(by)
    else:
        report(by)
        derived(by)
