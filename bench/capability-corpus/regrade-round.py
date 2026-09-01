#!/usr/bin/env python3
"""Re-grade a finished competitor round against `deobf.json`, uniformly.

WHY THIS EXISTS. The round drives `classify.py --names-strict`, which
grades against `manifest.json` and requires each payload's exact
BASENAME. The no-RAR corpus deliberately does not always have one: a leg
whose landed name is genuinely free carries the sentinel name
`(anywhere)` in the manifest and a null `path` in `deobf.json`, and its
`notes` say so in words ("keeping the hash name intact is acceptable").
No client can produce the string `(anywhere)`, so under `--names-strict`
EVERY arm is capped at manual-intervention on those legs and the round
cannot tell any two clients apart on them.

Measured 31 Aug 2026 on the wave51 round: nzbfast was graded
manual-intervention on n03-extensionless, n09-traversal and
n10-dup-filedesc while `roundtrip.py` - the corpus's own grader, reading
`deobf.json` - passed all three, and the delivered sha256 matched
byte-for-byte in each case. That is a GRADER artefact, not a client
defect, and it is not specific to nzbfast: it under-credits any client
that lands a legitimately-free name.

WHAT IS AND IS NOT GRADED HERE, because a cross-client grader has to be
narrower than a self-test:

  * `match_expected` - did every expected file land, at its expected
    path when the corpus names one, with the expected bytes. This is the
    question the round is asking and it is fair to every arm.
  * `containment_problems` - did anything land OUTSIDE the delivery
    directory. Fair, and load-bearing: n09-traversal exists precisely to
    catch a client that writes beside or above its output directory, and
    a grader that dropped this would score that defect as a pass.

  * closed-world / `allowed_extra` is DELIBERATELY NOT APPLIED. It is
    right for `roundtrip.py`, which grades nzbfast against a known
    output policy, and wrong here: every client leaves its own working
    files (logs, `_unpack` staging, `.nzb` copies, history), so
    enforcing it would fail competitors for being themselves rather than
    for missing a payload.
  * budget checks are not applied either - they read nzbfast's own log
    lines, which no other arm emits.

So this is STRICTLY the delivery question, asked identically of all
seven arms. It does not replace the round's own classification; it is
reported beside it, and where the two disagree the disagreement is the
finding.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import roundtrip as rt  # noqa: E402


def grade_arm(legdir, out):
    """Delivery-only verdict for one arm's output tree.

    Returns (ok, problems). A missing or empty tree is a failure with a
    named reason rather than an exception - a client that produced
    nothing is a result, not a crash.
    """
    # The deobf.json test comes FIRST and is an existence check, not a
    # try/except around `load_deobf`: that helper FALLS BACK to
    # manifest.json when there is no deobf.json, and raises outright when
    # there is neither. Both are wrong here - this grader is the no-RAR
    # tier's, the nested tier is graded content-anywhere by the round
    # itself, and a leg with neither file is not ours to judge.
    if not os.path.isfile(os.path.join(legdir, "deobf.json")):
        return None, ["no deobf.json - not a no-RAR leg"]
    if not os.path.isdir(out):
        return False, ["no output directory"]
    deobf = rt.load_deobf(legdir)
    if not deobf.get("expected"):
        return None, ["deobf.json names nothing expected"]
    profile = rt.probe_volume(out)
    entries, empty_dirs = rt.scan_tree(out)
    if not entries:
        return False, ["empty output directory"]
    problems, _ = rt.match_expected(deobf["expected"], entries, profile)
    problems += rt.containment_problems(out, entries, empty_dirs)
    return (not problems), problems


def selftest():
    """Drive every arm of this script against fixtures built on disk.

    The delivery verdict itself comes from `roundtrip.py`'s
    `match_expected` / `containment_problems`, which have their own
    selftest; what is unproven without this is the GLUE - and the glue is
    where the dangerous failure lives, because every mistake in it reads
    as a clean run rather than as an error. Specifically: a not-run leg
    must not be scored as a client failure (that is the shape that
    publishes a wrong competitor number off a partial round), an empty
    delivery must be a named failure rather than a pass, and a leg with
    no `deobf.json` must SKIP rather than count.
    """
    import shutil
    import tempfile

    fails = []

    def check(name, cond):
        print(f"  {'ok  ' if cond else 'FAIL'}  {name}")
        if not cond:
            fails.append(name)

    root = tempfile.mkdtemp(prefix="regrade-selftest-")
    try:
        legroot = os.path.join(root, "legs")
        runroot = os.path.join(root, "run")
        legdir = os.path.join(legroot, "leg1")
        os.makedirs(legdir)
        body = b"payload-bytes-for-the-selftest" * 64
        import hashlib
        digest = hashlib.sha256(body).hexdigest()
        json.dump(
            {
                "leg": "leg1",
                "schema": 2,
                "expected": [{"path": "want.bin", "sha256": digest, "bytes": len(body)}],
                "forbidden": [],
                "output_policy": {"closed_world": False, "allowed_extra": []},
            },
            open(os.path.join(legdir, "deobf.json"), "w"),
        )

        good = os.path.join(runroot, "leg1", "good")
        os.makedirs(good)
        open(os.path.join(good, "want.bin"), "wb").write(body)
        ok, probs = grade_arm(legdir, good)
        check("a correct delivery passes", ok is True and not probs)

        # Right bytes, WRONG name. This is the whole point of the round -
        # a client that delivers the payload hash-named has not
        # deobfuscated it - so it must NOT pass.
        misnamed = os.path.join(runroot, "leg1", "misnamed")
        os.makedirs(misnamed)
        open(os.path.join(misnamed, "Xk9pQ2mR"), "wb").write(body)
        ok, _ = grade_arm(legdir, misnamed)
        check("right bytes under the wrong name fails", ok is False)

        empty = os.path.join(runroot, "leg1", "empty")
        os.makedirs(empty)
        ok, probs = grade_arm(legdir, empty)
        check("an empty delivery fails, named", ok is False and probs == ["empty output directory"])

        ok, probs = grade_arm(legdir, os.path.join(runroot, "leg1", "absent"))
        check("a missing tree fails, named", ok is False and probs == ["no output directory"])

        # A leg with no deobf.json is not this grader's business, and it
        # must SKIP rather than raise - `roundtrip.load_deobf` falls back
        # to manifest.json and then throws, which is what this caught.
        bare = os.path.join(legroot, "bare")
        os.makedirs(bare)
        ok, _ = grade_arm(bare, good)
        check("a leg with no deobf.json SKIPS", ok is None)

        # The not-run arm: leg2 has a deobf.json but no directory under
        # the run root, so it must be reported separately and kept out of
        # every denominator.
        nolegs = os.path.join(legroot, "leg2")
        os.makedirs(nolegs)
        json.dump(
            {"leg": "leg2", "schema": 2, "expected": [{"path": "want.bin",
             "sha256": digest, "bytes": len(body)}], "forbidden": []},
            open(os.path.join(nolegs, "deobf.json"), "w"),
        )
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["regrade-round.py", legroot, runroot, "good", "misnamed"])
        out = buf.getvalue()
        check("a not-run leg is reported as NOT RUN", "NOT RUN (1)" in out and "leg2" in out)
        check("a not-run leg leaves the denominator at 1", "good             1/1" in out)
        check("the misnamed arm scores zero", "misnamed         0/1" in out)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print(f"\nregrade-round selftest: {8 - len(fails)}/8 checks passed")
    return 1 if fails else 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    if len(argv) < 3:
        sys.exit("usage: regrade-round.py <legroot> <runroot> [arm ...]\n"
                 "       regrade-round.py --selftest")
    legroot, runroot = argv[1], argv[2]
    arms = argv[3:] or [
        "nzbfast", "nzbget", "nzbget_testing", "sab", "rustnzb", "weaver", "weaver083",
    ]
    legs = sorted(
        d for d in os.listdir(legroot)
        if os.path.isfile(os.path.join(legroot, d, "deobf.json"))
    )
    if not legs:
        sys.exit(f"no legs with a deobf.json under {legroot}")
    tally = {a: [0, 0, []] for a in arms}
    notrun = []
    for leg in legs:
        legdir = os.path.join(legroot, leg)
        # A leg the round has not reached yet has NO directory under the
        # run root at all. Counting that as a failure would read as a
        # client defect, which is the single easiest way to publish a
        # wrong competitor number off a partial run - so it is reported
        # separately and excluded from every denominator.
        if not os.path.isdir(os.path.join(runroot, leg)):
            notrun.append(leg)
            continue
        row = []
        for a in arms:
            ok, probs = grade_arm(legdir, os.path.join(runroot, leg, a))
            if ok is None:
                row.append(f"{a}=skip")
                continue
            tally[a][1] += 1
            if ok:
                tally[a][0] += 1
                row.append(f"{a}=PASS")
            else:
                tally[a][2].append(leg)
                row.append(f"{a}=FAIL({probs[0][:60]})")
        print(f"{leg}: " + "  ".join(row))
    print()
    if notrun:
        print(f"=== NOT RUN ({len(notrun)}), excluded from every denominator ===")
        print("  " + ", ".join(notrun))
        print()
    print("=== delivery-only totals (deobf.json expected paths + containment) ===")
    for a in arms:
        got, n, fails = tally[a]
        print(f"  {a:16s} {got}/{n}" + (f"   missed: {', '.join(fails)}" if fails else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
