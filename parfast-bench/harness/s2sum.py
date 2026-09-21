#!/usr/bin/env python3
"""s2sum.py - reduce a jcross.ps1 STAGE-2 round to the table the constant is set from.

    s2sum.py <round.log> <logs-dir|legs.tsv> [--base s2off --test s2on --aa s2aa]
                                             [--emit-legs <path>]

WHY THIS EXISTS RATHER THAN an earlier summariser.
That file reads the mac driver's `STAGE` lines, which carry the whole phase
breakdown on the leg line itself. jcross.ps1 emits NO phase breakdown at all -
its LEG line stops at wall, cpu, peak_mb and the two stage LABELS - so on
Windows the timings live only in the per-leg `repair-timing` trace that the
harness captured to `<logs-dir>/r<rep>-m<rung>-<arm>.err`. This file is the
join: LEG lines for the arm/rep/rung/wall/cpu, the `.err` beside each one for
the control phase and the two stage marks.

WHY IT CAN ALSO READ AND WRITE A `legs.tsv`. The phase numbers arrive in 186
separate `.err` files for a six-rung round, which is a poor thing to bank: the
repo's convention is one round, one log, and the prior stage-2 round could
follow it because the mac driver put the whole phase breakdown on the leg line.
`--emit-legs` distils every per-leg number this reduction actually reads into
one greppable tab-separated file, and passing that file back in place of the
logs directory reproduces the tables exactly. So a banked round is the round
log plus one distillate, and it stays reducible by someone who never had the
box.

WHAT IT MEASURES. `forney::joint::JOINT_FACTOR_MIN_M` gates stage 2's FACTORED
evaluation. Both arms hold stage 1 on the additive product (NZBFAST_FORNEY_JOINT=1)
and differ only in NZBFAST_FORNEY_FACTOR, so the only thing that moves is the
arm that constant gates.

THE THREE RULES IT ENFORCES, each paid for by a round that got it wrong:

  * IT GATES ON BOTH STAGE LABELS, INDEPENDENTLY. Since 316f12ffb3 the two
    stages name their arms separately and all four combinations are reachable.
    `FALLBACK` in the stage-1 label means that leg ran the SHIPPED arithmetic
    and is not a measurement of this gate at all; the same word in stage 2 is
    how the round knows which of the two arms actually ran. A parser that trims
    at the first comma hides it, and did, for a whole 24-leg round. The
    complementary defect cost the crossover round half its self-check: a guard
    written as `"forney stage 1 (joint" in line` reports `no-label` for every
    baseline leg, because the shipped path prints `forney stage 1 (hankel, ...)`
    with no "joint" in it. So the gate here asserts the arm each label NAMES,
    and refuses a label it cannot read rather than skipping it.

  * IT PRINTS THE CONTROL BEFORE ANY TABLE. `verify targets + volume scan`
    reads and hashes the surviving members before a block is solved for. No arm
    of this change can reach it, so a systematic delta there is the BOX. The
    obvious candidate - stage 1's own mark - is NOT a control and must not be
    used as one: both stage marks are ATTRIBUTED shares of one fused wall, so a
    stage 2 running 20% slower mechanically pushes stage 1's attributed share
    DOWN at constant real cost, and the two numbers are then the same fact
    twice.

  * IT PAIRS WITHIN (rep, rung) AND NEVER ACROSS. Both arms of a pair share a
    damage seed and sit adjacent in the box's thermal history; a box that
    drifts over an hour moves both columns and only the pairing cancels it.
    Nothing is averaged across depths either - the crossover is the thing being
    located, and a single headline number over a ladder would erase it.

A delta smaller than its own rung's A/A floor is NOT a result. The floor is
printed beside the measurement at every depth so a reader can apply that rule
without trusting this file's arithmetic.
"""
import os
import re
import statistics
import sys

# The `.err` clause each phase prints, and the label fragments each stage
# prints. Read out of the engine's own wording rather than recomputed, so a
# fixture whose shape differs from the round author's belief cannot be
# silently relabelled.
CONTROL = "verify targets + volume scan"
STAGE1_RE = re.compile(r"forney stage 1 \((.+?)\): ([\d.]+)(s|ms)\b")
STAGE2_RE = re.compile(r"forney stage 2 \((.+?)\): ([\d.]+)(s|ms)\b")
BACKSUB_RE = re.compile(r"back-substitution \(([^)]*)\): ([\d.]+)(s|ms)\b")
# `+1.14s (total 1.14s)` - take the INCREMENT, never the running total.
CONTROL_RE = re.compile(re.escape(CONTROL) + r": \+([\d.]+)(s|ms|us)\b")


def secs(value, unit):
    return float(value) * {"s": 1.0, "ms": 1e-3, "us": 1e-6}[unit]


def read_err(path):
    """The phase marks and both stage labels from one leg's repair-timing trace."""
    out = {"stage1_label": "no-err", "stage2_label": "no-err"}
    if not os.path.exists(path):
        return out
    out["stage1_label"] = out["stage2_label"] = "no-label"
    # The trace is written by a Windows console in the box's own code page and
    # carries mojibake in the microsecond glyph; errors="replace" keeps the
    # ASCII digits, which is all any number here is read from.
    for line in open(path, errors="replace"):
        m = CONTROL_RE.search(line)
        if m:
            out["control"] = secs(m.group(1), m.group(2))
        m = STAGE1_RE.search(line)
        if m:
            out["stage1_label"] = m.group(1)
            out["stage1"] = secs(m.group(2), m.group(3))
        m = STAGE2_RE.search(line)
        if m:
            out["stage2_label"] = m.group(1)
            out["stage2"] = secs(m.group(2), m.group(3))
        m = BACKSUB_RE.search(line)
        if m:
            out["backsub"] = secs(m.group(2), m.group(3))
    return out


BUSY_REPAIR = re.compile(r"([\d.]+) foreign_after=")

# The keys a pre-fix `Require-QuietBox` repeats when it displaces a LEG line.
# The REPEATED KEY is the signature, not a non-numeric field: the line carries
# `foreign_cpu` twice - once as the literal "BOX-BUSY-WAIT" and once as the
# spike - and any key=value reader keeps the LAST, so the field a naive
# type-check inspects is a perfectly good number and the check passes. Credit
# to the parfast publication lane, whose first reader-side guard was exactly
# that type-check and found nothing on the line it was written for.
BUSY_KEYS = {"foreign_cpu", "try", "ceiling", "at", "ts"}


def parse_leg(line):
    """key=value off a jcross.ps1 LEG line, consuming single-quoted values whole.

    The engine's raw stage wording legitimately contains ` key=value ` of its
    own ("hankel, nseg=4, dft=mixed"), so a blind whitespace split files the
    rest of a label under `nseg` and loses it.
    """
    f, key, buf, quoting = {}, None, [], False
    repeated = set()
    for p in line.strip().split(" ")[1:]:
        if quoting:
            buf.append(p)
            if p.endswith("'"):
                f[key] = " ".join(buf).strip("'")
                quoting = False
            continue
        if "=" in p:
            k, rest = p.split("=", 1)
            if k.isidentifier():
                if k in f:
                    repeated.add(k)
                if rest.startswith("'") and not rest.endswith("'"):
                    key, buf, quoting = k, [rest], True
                else:
                    f[k] = rest.strip("'")
                continue
        if key and not quoting:
            f[key] = f.get(key, "") + " " + p
    # A LEG line written by a harness older than the 11 Sep fix to
    # plib.ps1's Require-QuietBox carries the load guard's own wait line
    # INSIDE it, because that function logged to the output stream and
    # returned its reading through the same stream:
    #   foreign_cpu=BOX-BUSY-WAIT try=1 foreign_cpu=343.8 ceiling=160 at=.. 59.4
    # Every field from foreign_cpu on is then displaced, and the naive read
    # takes the PRE-WAIT spike the guard had just waited out rather than the
    # quiet reading the leg actually ran under. The leg is sound - the guard
    # did its job - so this repairs the record rather than discarding it, and
    # flags the leg so the round can say how often the guard fired.
    if "BOX-BUSY-WAIT" in line:
        f["guard_fired"] = "1"
        m = BUSY_REPAIR.search(line)
        if m:
            # The LAST bare number before `foreign_after=` is the reading the
            # leg actually ran under, however many times the guard retried.
            f["foreign_cpu"] = m.group(1)
        repeated -= BUSY_KEYS
    # A measurement line has no legitimate reason to name a field twice. One
    # displacement is understood and repaired above; any OTHER repeated key is
    # a corruption whose shape is unknown, which means every field after it is
    # displaced by an unknown amount and cannot be read at all. Refuse rather
    # than guess - a leg that parses into plausible numbers is exactly the
    # failure this file exists to prevent.
    if repeated:
        f["corrupt_keys"] = ",".join(sorted(repeated))
    return f


# NEW FIELDS ARE APPENDED, NEVER INSERTED. `load_legs_tsv` reads the header out
# of the FILE and zips it against each row, so a banked distillate is
# self-describing and an old one stays readable whatever is added here - but
# only if the writer keeps growing at the end, because anything else silently
# re-points every column after the insertion for a reader that assumed the old
# order. `rig` was the last field until 11 Sep 2026 and `steal_pct` is now,
# which is the rule working rather than an exception to it. The distillate IS
# the banked artefact for a Windows stage-2 round (the phase numbers arrive in
# 186 separate `.err` files), so a field that did not survive it would be a
# field nobody downstream could check.
LEG_FIELDS = ("rep", "m", "arm", "wall", "cpu", "rc", "restored", "seed",
              "foreign_cpu", "foreign_after", "guard_fired", "corrupt_keys",
              "control", "stage1", "stage2", "backsub",
              "stage1_label", "stage2_label", "rig", "steal_pct")


def emit_legs(legs, path):
    with open(path, "w") as fh:
        fh.write("\t".join(LEG_FIELDS) + "\n")
        for f in legs:
            fh.write("\t".join(str(f.get(k, "")) for k in LEG_FIELDS) + "\n")


def load_legs_tsv(path):
    rows = []
    with open(path) as fh:
        head = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            if not line.strip():
                continue
            f = dict(zip(head, line.rstrip("\n").split("\t")))
            for k in ("control", "stage1", "stage2", "backsub"):
                if f.get(k):
                    f[k] = float(f[k])
                else:
                    f.pop(k, None)
            for k in ("guard_fired", "corrupt_keys"):
                if not f.get(k):
                    f.pop(k, None)
            rows.append(f)
    return rows


def load(logpath, logsdir):
    legs, box, binline, busy, harness = [], None, None, 0, []
    for line in open(logpath, errors="replace"):
        if line.startswith("BOX "):
            box = line.strip()
        elif line.startswith("BIN "):
            binline = line.strip()
        elif line.startswith("HARNESS ") or line.startswith("HARNESS-RIG "):
            harness.append(line.strip())
        # harness-rig-gate: a REDUCER, the same as jsum.py - it folds the LEG
        #   lines of a log it is handed and banks nothing. Its read of
        #   HARNESS-RIG two lines up is what stops a fold mixing harnesses.
        elif "BOX-BUSY-WAIT" in line and not line.startswith("LEG "):
            busy += line.count("BOX-BUSY-WAIT")
        elif line.startswith("LEG "):
            busy += line.count("BOX-BUSY-WAIT")
            f = parse_leg(line)
            if f.get("rep") in (None, "0"):
                continue  # the untimed warm-up
            f.update(read_err(os.path.join(
                logsdir, "r%s-m%s-%s.err" % (f["rep"], f["m"], f["arm"]))))
            legs.append(f)
    return legs, box, binline, busy, harness


def gate(legs, test_arm):
    """Refuse any leg that did not run the arm its name claims - either stage."""
    bad = []
    for f in legs:
        who = "%s rep=%s m=%s" % (f["arm"], f["rep"], f["m"])
        if f.get("corrupt_keys"):
            bad.append("%s: LEG line names %s more than once - fields after it "
                       "are displaced by an unknown amount"
                       % (who, f["corrupt_keys"]))
            continue
        s1, s2 = f["stage1_label"], f["stage2_label"]
        if "FALLBACK" in s1 or not s1.startswith("joint"):
            bad.append("%s: stage 1 ran %r - not the additive kernel" % (who, s1))
        ran_factor = s2.startswith("joint factor") and "FALLBACK" not in s2
        if s2 in ("no-err", "no-label", "unknown"):
            bad.append("%s: stage 2 label %r unreadable" % (who, s2))
            continue
        if ran_factor != (f["arm"] == test_arm):
            bad.append("%s: stage 2 ran %r" % (who, s2))
        if f.get("rc") != "0" or "/" in f.get("restored", "") and \
                f["restored"].split("/")[0] != f["restored"].split("/")[1]:
            bad.append("%s: rc=%s restored=%s" % (who, f.get("rc"), f.get("restored")))
    return bad


def harness_gate(legs):
    """Refuse a fold whose legs came from two different cuts of the harness.

    Every jcross.ps1 LEG line has carried `rig=<basename>:<sha16>[+...]` since
    11 Sep 2026 - one sha per file the round sourced, RE-READ at each leg -
    because the round-start `HARNESS` lines cannot see a file that changes at
    leg 40, and neither can `tools/bench-deploy-check.py`, which runs before
    the round. A DRIFT THAT REVERTS is invisible to both: on 11 Sep 2026 the
    deployed harness on intel-i5-10600kf diverged from origin/main for about twenty
    minutes and came back, because a queue owner added a refusal gate to the
    box before it landed in the repo.

    A round whose legs came from two harnesses is not one round. This file's
    whole method is pairing WITHIN a (rep, rung) on the premise that the only
    thing differing across a pair is the arm; two cuts of the driver break that
    premise in the one way nothing downstream can see, because both arms run,
    both restore, both print a wall, and every table is then arithmetic over
    two different experiments.

    An ABSENT stamp is a VALUE here and not a skip - a harness that GAINED the
    token mid-round is the same event as one whose sha moved - but a round with
    no stamp on ANY leg is merely old, and is reported rather than refused.
    """
    vals = {}
    for f in legs:
        vals.setdefault(f.get("rig") or "(absent)", []).append(f)
    if len(vals) < 2:
        return []
    out = ["this round's legs came from %d different harnesses:" % len(vals)]
    for val, rows in sorted(vals.items(), key=lambda kv: -len(kv[1])):
        out.append("  %-4d leg(s)  rig=%s" % (len(rows), val))
        out.append("            first rep=%s m=%s %s   last rep=%s m=%s %s"
                   % (rows[0].get("rep"), rows[0].get("m"), rows[0].get("arm"),
                      rows[-1].get("rep"), rows[-1].get("m"), rows[-1].get("arm")))
    out.append("Split by the CLOCK, leg by leg, and keep the discarded half as")
    out.append("`discarded-*.log` rather than deleting it, so the signature")
    out.append("stays findable (.claude/skills/bench-suite item 0e).")
    return out


def paired(legs, base, test, field):
    """Rung -> per-rep deltas, in percent, POSITIVE meaning `test` was faster."""
    idx = {}
    for f in legs:
        idx[(f["arm"], int(f["m"]), int(f["rep"]))] = f
    out = {}
    for (arm, m, rep), f in sorted(idx.items()):
        if arm != base:
            continue
        other = idx.get((test, m, rep))
        if other is None:
            continue
        a, b = f.get(field), other.get(field)
        if isinstance(a, str):
            a, b = float(a), float(b)
        if a and b:
            out.setdefault(m, []).append((a - b) * 100.0 / a)
    return out


def spread(d):
    med = max((abs(statistics.median(v)) for v in d.values()), default=0.0)
    worst = max((max(abs(x) for x in v) for v in d.values()), default=0.0)
    return med, worst


def table(title, d, floor=None):
    print("\n%s" % title)
    print("| m | n | median %s | worst %s | positive | floor %s |"
          % ("%", "%", "%"))
    print("|---:|---:|---:|---:|---:|---:|")
    for m in sorted(d):
        v = d[m]
        fl = ""
        if floor and m in floor:
            fl = "%.2f" % max(abs(x) for x in floor[m])
        print("| %d | %d | %+.2f | %+.2f | %d/%d | %s |"
              % (m, len(v), statistics.median(v), min(v),
                 sum(1 for x in v if x > 0), len(v), fl))


def absolute(legs, arms):
    print("\nabsolute stage-2 seconds (median of reps)")
    print("| m | " + " | ".join(arms) + " |")
    print("|---:|" + "---:|" * len(arms))
    for m in sorted({int(f["m"]) for f in legs}):
        cells = []
        for arm in arms:
            vals = [f["stage2"] for f in legs
                    if f["arm"] == arm and int(f["m"]) == m and "stage2" in f]
            cells.append("%.3f" % statistics.median(vals) if vals else "-")
        print("| %d | " % m + " | ".join(cells) + " |")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opt = dict(zip([a.lstrip("-") for a in sys.argv[1:] if a.startswith("--")],
                   [sys.argv[i + 1] for i, a in enumerate(sys.argv[1:], 1)
                    if a.startswith("--")]))
    base = opt.get("base", "s2off")
    test = opt.get("test", "s2on")
    aa = opt.get("aa", "s2aa")
    if args[1].endswith(".tsv"):
        legs = load_legs_tsv(args[1])
        box = binline = None
        harness = []
        for line in open(args[0], errors="replace"):
            if line.startswith("BOX "):
                box = line.strip()
            elif line.startswith("BIN "):
                binline = line.strip()
            elif line.startswith("HARNESS ") or line.startswith("HARNESS-RIG "):
                harness.append(line.strip())
        busy = sum(1 for f in legs if f.get("guard_fired"))
    else:
        legs, box, binline, busy, harness = load(args[0], args[1])
    if opt.get("emit-legs"):
        emit_legs(legs, opt["emit-legs"])
        print("wrote %s (%d legs)" % (opt["emit-legs"], len(legs)))
    # BEFORE the arm gate, because it is the wider question: the arm gate asks
    # whether each leg ran what it was asked to, and this asks whether the legs
    # are comparable to each other at all.
    mixed = harness_gate(legs)
    if mixed:
        print("REFUSED - " + mixed[0])
        for b in mixed[1:]:
            print("  " + b)
        sys.exit(1)
    bad = gate(legs, test)
    if bad:
        print("REFUSED - a leg ran an arm it was not asked for:")
        for b in bad[:40]:
            print("  " + b)
        sys.exit(1)

    print(box or "BOX unknown")
    print(binline or "BIN unknown")
    for h in harness:
        print(h)
    if legs and not any(f.get("rig") for f in legs):
        # Not a refusal - every log banked before 11 Sep 2026 predates the
        # field - but it IS the difference between a round that showed its
        # harness held still and one that asserted it.
        print("HARNESS: no `rig=` on any leg - this log predates the per-leg "
              "stamp and cannot show the harness held still for the round.")
    print("legs=%d busy_waits=%d arms=%s/%s floor=%s"
          % (len(legs), busy, base, test, aa))
    fg = [float(f["foreign_cpu"]) for f in legs if f.get("foreign_cpu")]
    fa = [float(f["foreign_after"]) for f in legs if f.get("foreign_after")]
    # `foreign_after` IS WINDOWS-ONLY, and this line used to assume otherwise.
    # `jcross.ps1` puts both readings on its LEG line; `jcross.py` - the unix
    # twin driving every round on a Linux or mac rig - emits `foreign_cpu`
    # alone. So `fa` is empty for every unix round and `statistics.median`
    # raised `no median for empty data`, which made this file unable to reduce
    # ANY unix round at all. Found 11 Sep 2026 by the Zen 4 sign round on
    # amd-epyc-vm, whose driver is `jcross.py`.
    #
    # The absence is REPORTED rather than filled in with a zero or a repeat of
    # the before-reading. A missing after-reading means the round cannot say
    # whether load arrived DURING a leg, and that is a real gap in what the
    # round can claim - stating it is the point. "Failing to find is failing":
    # a reduction that printed `after: median 0.0` would be asserting a quiet
    # box it never measured, which is the rubber-stamp shape this whole file
    # exists to refuse.
    #
    # Nothing else changes. The A/A floor, the control-phase refusal and both
    # stage-label gates never read this field.
    if not fg:
        print("foreign_cpu: NO readings on any leg - this log cannot say the "
              "box was quiet.")
    elif fa:
        print("foreign_cpu (%% of ONE core) before: median %.1f max %.1f   "
              "after: median %.1f max %.1f"
              % (statistics.median(fg), max(fg), statistics.median(fa), max(fa)))
    else:
        print("foreign_cpu (%% of ONE core) before: median %.1f max %.1f   "
              "after: NOT MEASURED (no `foreign_after` on this log - it predates "
              "the unix after-sample, so load arriving DURING a leg is invisible "
              "to this round)"
              % (statistics.median(fg), max(fg)))
    # STEAL, where the round measured it. A guest can read `foreign_cpu` quiet
    # all round and still be descheduled by its hypervisor, which is invisible
    # to a process table - see pdrv.cpu_stat_jiffies. Absent on a log that
    # predates the sample, and `n/a` off Linux; never summarised as 0.
    st = [float(f["steal_pct"]) for f in legs
          if f.get("steal_pct") not in (None, "", "n/a")]
    if st:
        print("steal (%% of all cpu time, per leg): median %.2f max %.2f"
              % (statistics.median(st), max(st)))
    else:
        print("steal: NOT MEASURED on this round (pre-dates the per-leg sample, "
              "or not Linux) - a co-tenant on the same host cannot be ruled out.")
    fired = [f for f in legs if f.get("guard_fired")]
    if fired:
        print("load guard fired on %d leg(s) - each WAITED and then re-read "
              "quiet, so the legs stand: %s"
              % (len(fired), ", ".join("rep%s m=%s %s" % (f["rep"], f["m"], f["arm"])
                                       for f in fired)))

    # THE CONTROL, BEFORE ANY TABLE. Read this line first.
    cm, cw = spread(paired(legs, base, test, "control"))
    am, aw = spread(paired(legs, base, aa, "control"))
    fm, fw = spread(paired(legs, base, aa, "stage2"))
    print("\nCONTROL  %s" % CONTROL)
    print("  A/B  worst median %5.2f%%  worst pair %5.2f%%" % (cm, cw))
    print("  A/A  worst median %5.2f%%  worst pair %5.2f%%" % (am, aw))
    print("stage-2 A/A floor  worst median %5.2f%%  worst pair %5.2f%%" % (fm, fw))
    if cm > max(fm, am):
        print("\n**THE CONTROL PHASE MOVED.** Nothing in this change can reach\n"
              "%s, so a systematic delta there is the box and the A/B legs\n"
              "were not comparable - read the box, not the tables below." % CONTROL)

    s2floor = paired(legs, base, aa, "stage2")
    print("\n## A/A floor (%s against %s - the same arm twice)" % (base, aa))
    table("wall", paired(legs, base, aa, "wall"))
    table("forney stage 2", s2floor)
    print("\n## A/B (%s = shipped stage 2, %s = FACTORED), positive = factored faster"
          % (base, test))
    table("wall", paired(legs, base, test, "wall"), paired(legs, base, aa, "wall"))
    table("back-substitution", paired(legs, base, test, "backsub"))
    table("forney stage 1 (ATTRIBUTED, see CONTROL - not an independent reading)",
          paired(legs, base, test, "stage1"))
    table("%s (the control - must not move)" % CONTROL,
          paired(legs, base, test, "control"))
    table("forney stage 2 (THE MEASUREMENT)",
          paired(legs, base, test, "stage2"), s2floor)
    table("user CPU seconds", paired(legs, base, test, "cpu"))
    absolute(legs, [base, test, aa])


if __name__ == "__main__":
    main()
