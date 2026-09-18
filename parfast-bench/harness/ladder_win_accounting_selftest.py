#!/usr/bin/env python3
"""ladder_win_accounting_selftest.py - does `ladder.Leg.run` actually record
the child's CPU and peak memory on THIS box?

WHY THIS EXISTS. `harness/ladder.py` recorded `cpu = -1.0` and
`peak = -1.0` on Windows and said so in its header: there was no `resource`
module and no `os.wait4`, so there was nothing to read. `winproc.py` landed on
17 Sep 2026 (`a4774eb01`) and answers both off the child's own process handle,
so the limit was closed - and `harness/windows_rig_lock_selftest.py`
is the standing reason a Windows arm is not shipped on reasoning: the last one
that was read every live process as dead.

WHAT IT CHECKS, on EVERY platform, so the POSIX arm is held to the same line
the Windows one is:

  1. a child that burns real CPU reports `cpu` > 0, and not wildly more than
     its own wall
  2. a child that touches a real allocation reports a `peak` big enough to
     have measured something
  3. rc and errlen still come through - a refusal must never read as a fast
     success (the rule the whole ladder is gated on)
  4. a FAILING child's rc reaches the record

THE TWO WINDOWS TRAPS IT IS BUILT AROUND, both measured on intel-core-ultra-9-386h on
17 Sep 2026 and written up in `pdrv._run_leg_win`:

  - `GetProcessTimes` stops at the DIRECT child, so the child here is
    `sys.executable` and NEVER a `.cmd`/`.bat` wrapper: through a wrapper the
    work is a generation down and `cpu` reads 0.0.
  - it carries the Windows clock's ~15.625 ms granularity, so the child BURNS
    CPU ON PURPOSE (~300 ms, about twenty ticks) rather than the test
    asserting around a floor it cannot see under.

It takes no rig lock, writes nothing outside a temp file, and runs in about a
second, so it is safe on a box somebody else is measuring on - its own timings
mean nothing and it asserts on none of them.

    python3 harness/ladder_win_accounting_selftest.py
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ladder  # noqa: E402 - after the sys.path line it needs

FAILURES = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("PASS" if ok else "FAIL", name,
                         ("" if ok else "  <- " + str(detail)[-400:])))
    if not ok:
        FAILURES.append(name)


# Burns ~300 ms of user CPU and holds ~64 MiB, then exits with the code it is
# given. `bytearray` and not a list: one contiguous private allocation, which
# is what both `ru_maxrss` and PeakWorkingSetSize are meant to see.
BURNER = (
    "import sys, time\n"
    "blob = bytearray(64 << 20)\n"
    "for i in range(0, len(blob), 4096): blob[i] = 1\n"
    "t = time.process_time()\n"
    "x = 0\n"
    "while time.process_time() - t < 0.30: x += 1\n"
    "sys.stderr.write('burned %d\\n' % x)\n"
    "sys.exit(int(sys.argv[1]))\n"
)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        leg = ladder.Leg()
        r = leg.run(sys.executable, ["-c", BURNER, "0"], tmp)

        check("rc of a clean child is 0", r["rc"] == 0, r)
        check("stderr reached the record", r["errlen"] > 0, r)
        check("wall covered the burn", r["wall"] >= 0.25, r)
        # The whole point: -1.0 is the sentinel this file exists to retire on
        # Windows, and a 0.0 would be the worse answer (a measurement that did
        # not happen, published as one).
        check("cpu was MEASURED, not sentinelled", r["cpu"] > 0.05, r)
        check("cpu is not nonsense (<= wall + a core's slack)",
              r["cpu"] <= r["wall"] + 1.0, r)
        check("peak was MEASURED, not sentinelled", r["peak"] > 0.0, r)
        # 64 MiB is allocated and touched; anything under ~16 MiB means the
        # figure is not this child's.
        check("peak saw the child's own allocation (>16 MiB)",
              r["peak"] > 16.0, r)
        # And an upper bound, so a box-wide or cumulative figure cannot pass:
        # a python holding 64 MiB is nowhere near 4 GiB.
        check("peak is this child's, not the box's (<4096 MiB)",
              r["peak"] < 4096.0, r)

        bad = leg.run(sys.executable, ["-c", BURNER, "3"], tmp)
        check("a FAILING child's rc reaches the record", bad["rc"] == 3, bad)
        check("a failing leg still carries cpu", bad["cpu"] > 0.05, bad)

    print("---")
    print("platform: %s (IS_WIN=%s)" % (sys.platform, ladder.IS_WIN))
    if FAILURES:
        print("FAILED %d: %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all arms passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
