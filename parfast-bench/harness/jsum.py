#!/usr/bin/env python3
"""jsum.py - reduce a jcross log to the paired table the constant is set from.

Reads LEG lines, pairs `fast` against `off` WITHIN a (rep, rung) - which is
where they share a damage seed and a position in the box's thermal history -
and reports the median paired delta, the count of positive pairs, and the
A/A floor measured the same way at the same depth from the `aa` arm.

Three things it refuses to do, each because a published round here has been
wrong in exactly that way before:

  * it does NOT average an unpaired `fast` column against an unpaired `off`
    column. A box that drifts over a 50-minute round moves both columns, and
    the pairing is what cancels it.
  * it does NOT accept a rung whose stage labels disagree across reps, or
    whose `fast` arm never engaged. A FALLBACK leg is not the arm under test,
    and an arm that silently declined is the defect the labels exist to catch.
  * it does NOT report a delta smaller than its own rung's A/A floor as a
    result. That column is printed beside every row so a reader can apply the
    same rule.

Usage:  jsum.py [--base off --test fast] <log> [<log> ...]

`--base`/`--test` name the two arms to pair. They default to the whole-arm
round's `off` and `fast`; the stage-2 round pairs `s2off` against `s2on`,
which is the same reduction over a different pair of arms.
"""
import sys, statistics, collections

BASE, TEST, AA = "off", "fast", "aa"


def parse(path):
    legs = []
    box = None
    bins = []
    harness = []
    retries = 0
    for line in open(path, errors="replace"):
        if line.startswith("BOX "):
            box = line.strip()
        elif line.startswith("BIN "):
            bins.append(line.strip())
        elif line.startswith("HARNESS ") or line.startswith("HARNESS-RIG "):
            harness.append(line.strip())
        elif line.startswith("BOX-BUSY-WAIT"):
            retries += 1
        if not line.startswith("LEG "):
            continue
        v = {}
        # stage labels contain spaces and commas, so a blind split on
        # whitespace mangles them; take key=value up to the next ` key=`.
        parts = line.strip().split(" ")
        key = None
        buf = []
        # A SINGLE-QUOTED value is consumed whole, because the engine's raw
        # stage wording legitimately contains ` key=value ` of its own -
        # "hankel, nseg=4, dft=mixed", "joint scheduler, m=704, gate 8192".
        # Without this, `nseg=4` starts a new field and the rest of the
        # label is silently filed under it. The quoting and this reader
        # landed together on 11 Sep 2026; older banked logs carry the raw
        # clause UNQUOTED and are handled by the ` key=` scan below, which
        # is why both paths are still here.
        quoting = False
        for p in parts[1:]:
            if quoting:
                buf.append(p)
                if p.endswith("'"):
                    quoting = False
                continue
            if "=" in p and not p.startswith("of"):
                k, rest = p.split("=", 1)
                if k.isidentifier():
                    if key:
                        v[key] = " ".join(buf).strip("'")
                    key, buf = k, [rest]
                    if rest.startswith("'") and not (
                        rest.endswith("'") and len(rest) > 1
                    ):
                        quoting = True
                    continue
            buf.append(p)
        if key:
            v[key] = " ".join(buf).strip("'")
        if v.get("rep") == "0":          # warm-up, discarded by design
            continue
        legs.append(v)
    return box, bins, harness, retries, legs


def pct(base, other):
    """Positive = `other` is FASTER than `base`."""
    return (base - other) / base * 100.0


def report(path):
    box, bins, harness, retries, legs = parse(path)
    print("=" * 78)
    print(path)
    if box:
        print(box)
    # THE `BIN` LINE IS THE AUDIT, so a log without one is refused rather
    # than summarised. It is what says which build a round measured, and
    # this campaign's central defect was a whole fleet measuring a binary
    # 31 minutes older than the gate that changed the answer - unanswerable
    # from wall times alone and a one-line grep with the header present.
    #
    # The realistic way to lose it is not carelessness, it is the OBVIOUS
    # extraction: `ssh box 'grep ^LEG round.log' > local.log` keeps every
    # number and drops the provenance, and the result still summarises
    # perfectly. Bank whole files.
    if not bins:
        print("REFUSED: no BIN line - this log has no provenance and cannot be")
        print("  summarised as a result. It is probably a `grep ^LEG` extract;")
        print("  re-pull the WHOLE file from the box that ran it.")
        return []
    for b in bins:
        print(b[:150])
    for h in harness:
        print(h[:150])
    # THE HARNESS MUST NOT HAVE CHANGED DURING THE ROUND, and this is the only
    # place a reader can find out. Every LEG line has carried
    # `rig=<basename>:<sha16>[+...]` since 11 Sep 2026 - one sha per file the
    # round sourced, re-read at each leg - because the round-start `HARNESS`
    # lines above cannot see a file that changes at leg 40, which is exactly
    # what happened on intel-i5-10600kf on 11 Sep 2026: the deployed harness diverged
    # from origin/main for about twenty minutes and came back. A DRIFT THAT
    # REVERTS is invisible to `tools/bench-deploy-check.py` and to those
    # HARNESS lines alike, because both run at a point in time.
    #
    # SO A ROUND WHOSE LEGS CAME FROM TWO HARNESSES IS NOT ONE ROUND, and it is
    # refused rather than folded. The pairing this file does is what makes a
    # delta readable, and it pairs `off` against `fast` WITHIN a (rep, rung) on
    # the assumption that the only thing differing between them is the arm. Two
    # cuts of the driver in one round breaks that assumption silently: both arms
    # run, both restore, both print a wall, and the table is arithmetic over
    # two different experiments.
    #
    # An ABSENT stamp is a value here, not a skip: a harness that GAINED the
    # token mid-round is the same event as one whose sha moved.
    stamps = collections.Counter(v.get("rig", "(absent)") for v in legs)
    if len(stamps) > 1:
        print("REFUSED: this round's legs came from %d different harnesses, so"
              % len(stamps))
        print("  it is not one round and must not be folded into one table.")
        for val, n in sorted(stamps.items(), key=lambda kv: -kv[1]):
            where = [v for v in legs if v.get("rig", "(absent)") == val]
            print("    %-4d leg(s)  rig=%s" % (n, val))
            print("             first %s  last %s"
                  % (where[0].get("ts", "?"), where[-1].get("ts", "?")))
        print("  Split by the CLOCK, leg by leg, and keep the discarded half as")
        print("  `discarded-*.log` rather than deleting it, so the signature")
        print("  stays findable (.claude/skills/bench-suite item 0e).")
        return []
    if legs and "(absent)" in stamps:
        # Not a refusal - every log banked before 11 Sep 2026 predates the
        # field - but it IS the difference between a round that showed its
        # harness held still and one that asserted it.
        print("HARNESS: no `rig=` on any leg - this log predates the per-leg "
              "stamp and cannot show the harness held still for the round.")
    if retries:
        # Not a failure: that harness waits rather than aborting, and the
        # legs ran once the box quieted. It IS evidence about the box, and
        # a round that needed retries is not the same evidence as one that
        # needed none even when both are clean.
        print("NOISE: %d BOX-BUSY-WAIT retr%s - the guard was absorbing "
              "contention on this box" % (retries, "y" if retries == 1 else "ies"))
    by = collections.defaultdict(dict)
    for v in legs:
        # TWO LEG SCHEMAS ARE IN `rounds/`. jcross names the arm
        # `arm=`; the older publication harness (mfast/mcross/mfull) names
        # it `tool=`, because there the arms were different BINARIES and
        # only later became two arms of one. Reading both is what lets a
        # before/after be summarised by one reducer - which is the whole
        # point of banking the pre-gate rounds beside the post-gate ones.
        label = v.get("arm") or v.get("tool")
        if label is None:
            continue
        by[(int(v["rep"]), int(v["m"]))][label] = v
    rungs = sorted({m for _, m in by})
    arms_seen = sorted({a for cell in by.values() for a in cell})
    if BASE not in arms_seen or TEST not in arms_seen:
        print("REFUSED: this log has arms %s; asked to pair %r against %r."
              % (arms_seen, BASE, TEST))
        print("  Name them with --base/--test. The pre-gate publication rounds")
        print("  use `parfast` and `fast`; jcross uses `off` and `fast`.")
        return []
    # THE NEGATIVE CONTROL, PRINTED ABOVE THE TABLE AND NOT IN IT, because it
    # is a verdict about the BOX and a reader has to reach it before any row.
    # `ctrl_s` is `verify targets + volume scan`: the pass that reads and
    # hashes every target before the Forney gate is consulted, so no arm of
    # this round can reach it, at any rung.
    #
    # Neither stage mark can do this job. Both are attributed SHARES of one
    # fused wall, so a stage mark that holds still says the attribution held
    # still, not that the box did.
    #
    # It is reported rather than enforced, and deliberately: the threshold at
    # which a moving control voids a round is a judgement about that round's
    # effect size, and a hard cut here would either void readable rounds or
    # rubber-stamp noisy ones. What is mechanical is the COMPARISON - the
    # control's drift against the A/A floor it has to beat - and that is
    # printed so nobody has to compute it while reading.
    ctrl_ab, ctrl_aa = [], []
    for (r, m), cell in by.items():
        b = cell.get(BASE)
        if not b:
            continue
        try:
            base_c = float(b.get("ctrl_s", "n/a"))
        except ValueError:
            continue
        for arm, sink in ((TEST, ctrl_ab), (AA, ctrl_aa)):
            c = cell.get(arm)
            if not c:
                continue
            try:
                other = float(c.get("ctrl_s", "n/a"))
            except ValueError:
                continue
            if base_c > 0:
                sink.append(abs(pct(base_c, other)))
    if ctrl_ab or ctrl_aa:
        for name, vals in (("A/B", ctrl_ab), ("A/A", ctrl_aa)):
            if vals:
                print("CONTROL %s verify_targets_volume_scan: median drift "
                      "%.2f%%, worst pair %.2f%% over %d pair(s)"
                      % (name, statistics.median(vals), max(vals), len(vals)))
    else:
        # Not a refusal - every log banked before 11 Sep 2026 predates the
        # field - but it IS the difference between a round that showed its
        # box was quiet and one that asserted it.
        print("CONTROL: absent (no ctrl_s on any leg) - this log cannot show "
              "the box was quiet; the A/A floor is its only noise evidence.")
    print("%-8s %7s %7s   %-9s %-6s   %-9s   %s"
          % ("m", BASE + "_s", TEST + "_s", TEST + "%", "pos", "aa%|floor",
             "stage1/stage2 (" + TEST + " arm)"))
    rows = []
    for m in rungs:
        reps = sorted(r for r, mm in by if mm == m)
        d_fast, d_aa, walls_off, walls_fast = [], [], [], []
        labels = set()
        bad = []
        for r in reps:
            cell = by[(r, m)]
            if BASE not in cell or TEST not in cell:
                continue
            o, f = float(cell[BASE]["wall"]), float(cell[TEST]["wall"])
            walls_off.append(o)
            walls_fast.append(f)
            d_fast.append(pct(o, f))
            # `-` rather than `None` for a stage the log never carried: the
            # pre-gate harness parsed stage 1 only, because stage 2 did not
            # have an arm of its own to name until 11 Sep 2026. An absent
            # label is a fact about the harness, not a fallback.
            labels.add("%s | %s" % (cell[TEST].get("stage1", "-"),
                                    cell[TEST].get("stage2", "-")))
            for arm in (BASE, TEST, AA):
                c = cell.get(arm)
                if c and c["rc"] != "0":
                    bad.append("%s rc=%s" % (arm, c["rc"]))
                if c and c["restored"].split("/")[0] != c["restored"].split("/")[1]:
                    bad.append("%s restored=%s" % (arm, c["restored"]))
            if AA in cell:
                d_aa.append(pct(o, float(cell[AA]["wall"])))
        if not d_fast:
            continue
        med = statistics.median(d_fast)
        pos = sum(1 for x in d_fast if x > 0)
        floor = max(abs(x) for x in d_aa) if d_aa else float("nan")
        lab = "; ".join(sorted(labels))
        rows.append((m, med, pos, len(d_fast), floor, lab))
        flag = ""
        if d_aa and abs(med) < floor:
            flag = "  <- under its own A/A floor"
        if bad:
            flag += "  !! " + "; ".join(sorted(set(bad)))
        print("%-8d %7.2f %7.2f   %+8.2f%% %d/%-4d   %8.2f%%   %s%s"
              % (m, statistics.median(walls_off), statistics.median(walls_fast),
                 med, pos, len(d_fast), floor, lab, flag))
    # The positive control. If the deepest rungs do not reproduce the known
    # win the round is measuring something else and every row above is void.
    deep = [r for r in rows if r[0] >= 12288]
    if deep:
        ok = all(r[1] > 3.0 and r[2] >= (r[3] + 1) // 2 for r in deep)
        print("POSITIVE-CONTROL %s: deepest rungs %s"
              % ("HOLDS" if ok else "**FAILED - round is void**",
                 ", ".join("m=%d %+.1f%% %d/%d" % (r[0], r[1], r[2], r[3]) for r in deep)))
    elif rows:
        # FAILING TO FIND IS FAILING, and silence is the one thing this line
        # must not be. A log with no rung at or past 12,288 gets no control
        # verdict at all, and until 11 Sep 2026 that absence printed as
        # nothing - indistinguishable, to a reader scanning for the word
        # HOLDS, from a round whose control was never checked. The n axis
        # makes it reachable in ordinary use rather than by mistake: the
        # 0.5x rung of a set-shape sweep is n = 8,192 source blocks, so its
        # ladder CANNOT carry a 12,288 rung and no amount of care will put
        # one there. Say so, and say what a reader has to do instead.
        print("POSITIVE-CONTROL ABSENT: deepest rung here is m=%d, and this "
              "check needs one at or past 12288." % max(r[0] for r in rows))
        print("  This log has NO positive control of its own. It is not void "
              "and it is not confirmed - it is unverified, and must be read")
        print("  beside a round on the same box and binary that does carry "
              "one. Do not quote it alone.")
    return rows


if __name__ == "__main__":
    args = sys.argv[1:]
    while args and args[0].startswith("--"):
        flag, val, args = args[0], args[1], args[2:]
        if flag == "--base":
            BASE = val
        elif flag == "--test":
            TEST = val
        elif flag == "--aa":
            AA = val
        else:
            sys.exit("unknown flag %r" % flag)
    for p in args:
        report(p)
