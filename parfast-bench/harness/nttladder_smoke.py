#!/usr/bin/env python3
"""nttladder_smoke.py - run `nttladder.py` END TO END, on any platform, in
seconds, against a stub tool and a toy fixture.

Written 17 Sep 2026 with the Windows port of `pdrv.py` (claim
`nttladder-windows-port-17sep`). `pdrv_port_selftest.py` beside this covers the
PRIMITIVES - the foreign-CPU arithmetic, the rig lock, the child accounting.
This covers the thing a round actually runs: the driver itself, all the way
from `RUNGS` parsing through damage, the leg, the SHA gate, the restore, the
stderr dispatch, the jsonl record and the LEG line.

WHY A STUB TOOL RATHER THAN parfast. The real cell is 10 x 1,020 MiB of
urandom and hours of rig lock (section 8.18.3). Nothing in the DRIVER needs
that: every platform-specific thing the port touched is exercised by a leg that
lasts 40 ms, and the one thing a stub cannot check - whether the numbers are
right - was never this file's question. So this is a SMOKE TEST and says so:
passing it means the driver runs on this box, NOT that a ladder measured here
would be sound.

THE STUB "REPAIRS" BY COPYING THE PRISTINE MEMBERS BACK, which is what makes
the round complete rather than abort at leg one: `nttladder.run_leg` gates every
leg on SHA-256 restoration and raises "that is damage, not data" on anything
else, exactly as it should. It also prints realistic `ntt syndromes` lines to
STDERR, so `dispatch()`'s regex, the per-window `(S, t)` points and the unit
table are all exercised on real text rather than asserted about.

WHAT IT DELIBERATELY DOES NOT DO: it never touches `~/.parfast-rig.lock` (it
takes no lock, because `nttladder.py` does not - the round runner around it
does), it writes only inside a temp directory, and it runs no cargo and no
parfast. It is safe to run on a box somebody else is measuring on, though the
quiet gate below is disabled for it and so its own timings mean nothing.

    python3 harness/nttladder_smoke.py
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

STUB = r'''
import os, shutil, sys
# The stub tool. argv is parfast's: r -t<N> [-m<N>] -q set.par2
#
# IT MODELS THE ENGINE'S WINDOW SPLIT, which is what makes the ARENA_PROBE arm
# a test rather than a smoke check. A PLANTED arena line lives in the
# environment - arenas(m) = SMOKE_ARENA_A * m + SMOKE_ARENA_B - and the stub
# splits the present sources exactly as the engine does: the first window
# takes floor((budget - arenas) / slice) sources and the rest follow greedily,
# which is the behaviour read off 8.18's own banked probe legs (m=1,000,
# budget 6,090,948,251 -> [5704, 3496] over 9,200 present). The driver's
# arena_pass() must then recover A and B from two probe legs alone.
pristine = os.environ["SMOKE_PRISTINE"]
slice_ = int(os.environ["SMOKE_SLICE"])
A = float(os.environ.get("SMOKE_ARENA_A", "0"))
B = float(os.environ.get("SMOKE_ARENA_B", "0"))

# `m` is not passed to the tool, so COUNT IT, the way a real engine learns it:
# from the set itself. A damaged slice is one that differs from pristine.
names = sorted(n for n in os.listdir(pristine) if n.endswith(".bin"))
m, total = 0, 0
for name in names:
    good = open(os.path.join(pristine, name), "rb").read()
    have = open(os.path.join(os.getcwd(), name), "rb").read()
    for off in range(0, len(good), slice_):
        total += 1
        if good[off:off + slice_] != have[off:off + slice_]:
            m += 1
present = total - m

w = sys.stderr
budget = os.environ.get("NZBFAST_NTT_BUDGET")
if budget is None:
    # A `host` rung: no budget named, one window over everything. A real
    # engine would use RAM/4; the count is what this test reads.
    windows = [present]
else:
    arenas = A * m + B
    s_first = int((int(budget) - arenas) // slice_)
    if s_first < 1:
        # The row gate refusing is a FOLD, and a fold prints no window. The
        # driver has to notice that on a probe rather than divide by it.
        w.write("fold: refused by the row gate\n")
        w.flush()
        for name in names:
            shutil.copyfile(os.path.join(pristine, name), os.path.join(os.getcwd(), name))
        sys.stdout.write("repaired (folded)\n")
        raise SystemExit(0)
    windows, left = [], present
    while left > 0:
        take = min(s_first, left)
        windows.append(take)
        left -= take
for n in windows:
    # A real leg's per-window time is not modelled - this test never reads a
    # timing - but the LINE has to parse, so it carries a plausible one.
    w.write("ntt syndromes (m=%d, needed=%d, n=%d, W=512, threads=8): 12.5ms\n"
            % (m, m, n))
# `ntt window` undercounts by one - the tail window prints no such line - which
# is the trap nttladder.dispatch() documents; reproduced rather than asserted.
for _ in windows[:-1]:
    w.write("ntt window (%d bytes, %d slices, dense): 1.5ms\n" % (slice_, windows[0]))
w.write("in 1 slab(s) of %d B\n" % slice_)
w.write("feed+fold+solve: +40.0ms\n")
w.write("final verify: +5.0ms\n")
w.write("patch: +1.0ms\n")
w.write("back-substitution (dense): +3.0ms\n")
w.write("verify targets + volume scan: +2.0ms\n")
w.write("load recovery: +4.0ms\n")
w.flush()
for name in names:
    shutil.copyfile(os.path.join(pristine, name), os.path.join(os.getcwd(), name))
# BURN MEASURABLE CPU ON PURPOSE. `GetProcessTimes` has the Windows clock's
# ~15.625 ms granularity, so a child that finishes inside one tick reads 0.0
# and an assertion that `cpu > 0` would be a coin toss rather than a test.
# A real leg is seconds and never near this floor; this buys the same margin
# in 200 ms.
x = 0
for i in range(3000000):
    x += i
sys.stdout.write("repaired %d\n" % x)
'''



def build_fixture(root, members=2, size=1048576):
    fix = os.path.join(root, "fix")
    pristine, work = os.path.join(fix, "pristine"), os.path.join(fix, "work")
    os.makedirs(pristine)
    os.makedirs(work)
    gold = []
    for i in range(members):
        name = "m%02d.bin" % i
        # Deterministic, not urandom: this fixture is never measured, and a
        # reproducible one makes a failure reproducible too.
        blob = (b"".join(bytes([(i * 37 + j) & 0xFF]) for j in range(256)) * (size // 256))
        for d in (pristine, work):
            with open(os.path.join(d, name), "wb") as fh:
                fh.write(blob)
        gold.append("%s  %s" % (hashlib.sha256(blob).hexdigest(), name))
    # A recovery volume, so `remove_strays`' keep set is non-trivial.
    with open(os.path.join(work, "set.par2"), "wb") as fh:
        fh.write(b"PAR2\0PKT" + b"\0" * 64)
    with open(os.path.join(fix, "gold.sha"), "w") as fh:
        fh.write("\n".join(gold) + "\n")
    return fix


def main():
    failures = []

    def check(name, cond, detail=""):
        print("%-4s %s%s" % ("ok" if cond else "FAIL", name,
                             ("  - " + detail) if detail and not cond else ""))
        if not cond:
            failures.append(name)

    with tempfile.TemporaryDirectory() as root:
        fix = build_fixture(root)
        fix_work = os.path.join(fix, "work")
        # THE STUB MUST BE THE DIRECT CHILD, AND THAT IS NOT A DETAIL - it is
        # the thing this test exists to prove on Windows. `pdrv.run_leg`
        # measures the child it launched and nothing below it: POSIX reads the
        # rusage `os.wait4` returns for the pid it reaped, and the Windows arm
        # reads `GetProcessTimes` on that pid's handle. Both stop at the direct
        # child. A wrapper script therefore measures the WRAPPER - and the
        # first cut of this test used one, a `.cmd` on Windows, which put
        # python a generation down and made `cpu` read 0.0 on eleven of sixteen
        # legs while the POSIX `#!/bin/sh` + `exec` wrapper became python and
        # read correctly. That asymmetry is the shell's, not the port's, and a
        # real round never has it: `BIN` there is `parfast.exe`, one process,
        # launched directly.
        #
        # So the interpreter itself is `BIN`, and the stub is a file named `r`
        # inside the work directory - which is where `nttladder` sets the
        # child's cwd, and `r` is the first element of the argv it builds
        # (`r -t8 -q set.par2`). `python r -t8 -q set.par2` runs it with the
        # rest as script arguments, on both platforms, with no wrapper at all.
        # `r` is created BEFORE the driver imports, so it is inside the `KEEP`
        # snapshot `STRAYS=1` restores to.
        with open(os.path.join(fix_work, "r"), "w") as fh:
            fh.write(STUB)
        bins = [sys.executable, sys.executable]

        env = dict(os.environ)
        env.update({
            "SCRATCH": root, "BIN": bins[0], "BIN_AA": bins[1],
            "SMOKE_PRISTINE": os.path.join(root, "fix", "pristine"),
            "SMOKE_SLICE": "65536",
            "SLICE": "65536", "M": "4", "REPS": "2", "SEED": "2001",
            "THREADS": "8", "STRAYS": "1", "TAG": "smoke",
            "RUNGS": "w1=16777216000,w2=8388608000+M6,ctl_host=host,ctl_m16=m16000",
            # The quiet gate would refuse on any box carrying load, and this
            # test asserts nothing about time. Ten tries at thirty seconds is
            # also five minutes a leg on a busy box, which no smoke test can
            # pay. See pdrv.set_quiet_budget.
            "PDRV_QUIET_TRIES": "0",
        })
        # THE QUIET GATE HAS TO BE LIFTED, AND A `runpy` SHIM IS HOW - not an
        # edit to `nttladder.py`, which must stay byte-identical to the copy
        # sections 8.11 through 8.18 invoked. `PDRV_QUIET_TRIES=0` only removes
        # the WAIT; `require_quiet_box` still takes one sample and exits 18
        # over the ceiling, and the ceiling has no env dial. Section 8.13 of
        # an internal note reached for the same
        # shim for the same reason. A smoke test asserts nothing about time, so
        # lifting it costs nothing here and would be indefensible in a round.
        shim = os.path.join(root, "shim.py")
        with open(shim, "w") as fh:
            fh.write(
                "import runpy, sys\n"
                "sys.path.insert(0, __HERE__)\n"
                "import pdrv\n"
                "pdrv.FOREIGN_CPU_CEILING_FRAC = 1e9\n"
                "pdrv.FOREIGN_CPU_FLOOR_PCT = 1e11\n"
                "pdrv.PER_CORE_CEILING_PCT = 1e9\n"
                "pdrv.QUIET_TRIES = 0\n"
                "runpy.run_path(__LADDER__, run_name='__main__')\n"
                .replace("__HERE__", repr(HERE))
                .replace("__LADDER__", repr(os.path.join(HERE, "nttladder.py"))))
        res = subprocess.run([sys.executable, shim],
                             cwd=root, env=env, capture_output=True, text=True)
        out = res.stdout
        print(out.rstrip()[-2000:] if res.returncode else "", file=sys.stderr if res.returncode else sys.stdout)
        check("the ladder ran to completion", res.returncode == 0,
              (out + res.stderr)[-1500:])
        check("it printed ALL DONE", "ALL DONE" in out)
        legs = os.path.join(root, "legs.jsonl")
        check("it banked a legs.jsonl", os.path.exists(legs))
        if not os.path.exists(legs):
            return 1
        recs = [json.loads(l) for l in open(legs) if l.strip()]
        # 4 rungs x 2 reps x 2 arms
        check("one record per rung per rep per arm", len(recs) == 16,
              "got %d" % len(recs))
        check("every leg rc 0 and byte-exact",
              all(r["rc"] == 0 and r["ok"] and not r["bad"] for r in recs),
              repr([r for r in recs if r["rc"] or not r["ok"]][:1]))
        check("dispatch found the ntt path", all(r["path"] == "ntt" for r in recs))
        check("the tail window prints no `ntt window` line, so it undercounts by one",
              all(r["ntt_windows"] == r["ntt_syn_calls"] - 1 for r in recs),
              repr([(r["ntt_syn_calls"], r["ntt_windows"]) for r in recs]))
        check("per-window (S, t) points survive to the record",
              all(r["win_points"] and r["win_sources"] == 32 - r["m"] for r in recs),
              repr([(r["m"], r["win_sources"]) for r in recs]))
        # The unit table is checked on the PER-POINT values, which `_sec`
        # rounds to 4 places, and not on `syn_total`, which is rounded to 3 and
        # so cannot resolve the 2.1 ms tail window at all (0.0273 -> 0.027).
        # That rounding is the driver's and is left alone; the fit is taken on
        # the points.
        check("the ms unit table resolved on the per-window points",
              all(p["t"] == 0.0125 for r in recs for p in r["win_points"]),
              repr(sorted({p["t"] for r in recs for p in r["win_points"]})))
        check("the term parser read feed+fold+solve and back-substitution",
              recs[0]["feed_fold_solve"] == 0.04 and recs[0]["back_sub"] == 0.003,
              repr((recs[0]["feed_fold_solve"], recs[0]["back_sub"])))
        check("the +M rung carried its own damage count",
              sorted({r["m"] for r in recs}) == [4, 6],
              repr(sorted({r["m"] for r in recs})))
        check("the m control carried its -m argument",
              {r["m_arg"] for r in recs} == {None, "16000"},
              repr({r["m_arg"] for r in recs}))
        # THE ASSERTION THE WINDOWS PORT IS ACTUALLY FOR. On POSIX this is
        # `os.wait4`'s rusage and has always worked; on Windows it is
        # `GetProcessTimes` on the child's own handle, read AFTER the child
        # exited, which is the substitute this port had to find because
        # `os.wait4` does not exist there.
        check("child CPU was measured on this platform",
              all(r["cpu"] > 0.0 for r in recs), repr([r["cpu"] for r in recs]))
        check("a peak was measured on this platform",
              all(r["peak_mb"] > 0.0 for r in recs), repr([r["peak_mb"] for r in recs]))
        check("STRAYS=1 left the work directory as it found it",
              sorted(os.listdir(fix_work)) == ["m00.bin", "m01.bin", "r", "set.par2"],
              repr(sorted(os.listdir(fix_work))))
        check("steal is a number under a hypervisor and n/a otherwise, never 0.0 asserted",
              all(r["steal_pct"] == "n/a" or isinstance(r["steal_pct"], float)
                  for r in recs), repr({str(r["steal_pct"]) for r in recs}))
        check("BOX and BIN provenance lines were printed",
              "BOX   " in out and "BIN   " in out)
        # THE BACK-COMPATIBILITY ASSERTION, and it is the one that protects
        # eight banked sections. A round with no `k` rung must print the
        # RUNGS line in the FIVE-element shape every invocation from 8.11
        # through 8.18 produced, because those logs are the provenance of
        # an internal note and a reducer
        # reading them must not meet a field it has never seen.
        rungs_line = [l for l in out.splitlines() if l.startswith("RUNGS ")]
        check("RUNGS keeps its 5-element shape when no rung carries a k",
              len(rungs_line) == 1
              and all(len(e) == 5 for e in json.loads(rungs_line[0][6:])),
              repr(rungs_line))
        check("and ARENA_PROBE is silent when it is off",
              not any(l.startswith("ARENA") for l in out.splitlines()))

        # -------------------------------------------------------------------
        # ARENA_PROBE=1 - does the driver RECOVER a planted arena term?
        # -------------------------------------------------------------------
        # The stub carries a known arenas(m) = A*m + B and splits its windows
        # on it exactly as the engine does. Two probe legs at the ends of the
        # round's own m axis are all arena_pass() gets, so if the fit comes
        # back as A and B the measurement is right end to end - which is the
        # whole of handoff item 3, and the thing that a hand-derived or
        # code-derived term got wrong by 59% at the top rung.
        A, B = 60652.0, 49218847.0        # 8.18.3's measured GFNI figures
        probe_env = dict(env)
        probe_env.update({
            "ARENA_PROBE": "1", "SMOKE_ARENA_A": str(A), "SMOKE_ARENA_B": str(B),
            "OUT": "arena.jsonl", "TAG": "arena", "REPS": "1",
            # Two m rungs, so the probe has an axis to fit on, and a `k` rung
            # whose budget the driver must compute for itself.
            "RUNGS": "a_m4=%d+M4,a_m6=%d+M6,a_k2=k2+M4"
                     % (int(A * 4 + B) + 20 * 65536, int(A * 6 + B) + 8 * 65536),
        })
        res2 = subprocess.run([sys.executable, shim], cwd=root, env=probe_env,
                              capture_output=True, text=True)
        out2 = res2.stdout
        check("the ARENA_PROBE round ran to completion", res2.returncode == 0,
              (out2 + res2.stderr)[-1500:])
        fit = [l for l in out2.splitlines() if l.startswith("ARENA-FIT")]
        check("it printed a fitted arena line", len(fit) == 1, repr(fit))
        if fit:
            import re as _re
            got = _re.search(r"= ([0-9.]+) \* m \+ ([0-9]+)", fit[0])
            check("the fit RECOVERS the planted slope",
                  got and abs(float(got.group(1)) - A) < 1.0, fit[0])
            check("the fit RECOVERS the planted intercept",
                  got and abs(float(got.group(2)) - B) <= float(65536), fit[0])
        check("the probe legs were banked OUTSIDE the ladder's own jsonl",
              os.path.exists(os.path.join(root, "arena.jsonl.probe.jsonl")))
        arena_recs = [json.loads(l) for l in open(os.path.join(root, "arena.jsonl")) if l.strip()]
        check("no probe leg leaked into the ladder's population",
              all(not r["rung"].startswith("probe-") for r in arena_recs)
              and len(arena_recs) == 6, "%d recs" % len(arena_recs))
        check("every leg records its own realised arena term",
              all(abs(r["arenas"] - (A * r["m"] + B)) <= 65536
                  for r in arena_recs if r["arenas"] is not None),
              repr([(r["m"], r["arenas"]) for r in arena_recs][:3]))
        # The k rung: the driver had to compute its budget from the fit, and
        # the engine then had to split it into exactly k windows.
        k_legs = [r for r in arena_recs if r["rung"] == "a_k2"]
        check("the k2 rung got a budget and split into exactly 2 windows",
              k_legs and all(r["ntt_syn_calls"] == 2 for r in k_legs),
              repr([(r["rung"], r["ntt_budget"], r["ntt_syn_calls"]) for r in k_legs]))
        check("it printed a RUNG-BUDGET line for the k rung",
              any(l.startswith("RUNG-BUDGET a_k2") for l in out2.splitlines()))
        check("it priced what the probe bought against the scaled closed form",
              any(l.startswith("ARENA-SCALED-WOULD-BE") for l in out2.splitlines()))
        check("it predicted every rung before running any of them",
              len([l for l in out2.splitlines() if l.startswith("PREDICT")]) == 3,
              repr([l for l in out2.splitlines() if l.startswith("PREDICT")]))

        # A `k` rung without ARENA_PROBE must be refused AT STARTUP, not at
        # leg one - there is nothing to compute its budget from.
        bad_env = dict(env)
        bad_env.update({"RUNGS": "x=k2+M4", "OUT": "bad.jsonl"})
        res3 = subprocess.run([sys.executable, shim], cwd=root, env=bad_env,
                              capture_output=True, text=True)
        check("a k rung without ARENA_PROBE is refused at startup",
              res3.returncode != 0 and "ARENA_PROBE=1" in (res3.stdout + res3.stderr),
              (res3.stdout + res3.stderr)[-400:])

    print("---")
    if failures:
        print("FAILED %d: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("nttladder ran end to end on %s. This is a SMOKE TEST over a stub "
          "tool: it says the DRIVER works here, never that a ladder measured "
          "here would be sound." % (os.name == "nt" and "windows" or sys.platform))
    return 0


if __name__ == "__main__":
    sys.exit(main())
