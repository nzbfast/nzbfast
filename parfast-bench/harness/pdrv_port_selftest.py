#!/usr/bin/env python3
"""pdrv_port_selftest.py - does the Windows port of `pdrv.py` hold, and is the
POSIX half still byte-for-byte the one that banked sections 8.11 to 8.18?

Written 17 Sep 2026 with the port (claim `nttladder-windows-port-17sep`,
an internal note item 1).

THE SPLIT, AND WHY IT IS THE ONE THAT MATTERS. Most of what a port like this
gets wrong is not Windows-specific at all, and waiting for a Windows box to
find out is how `riglock_state._win_pid_alive` shipped a check that read EVERY
live process as dead (`windows_rig_lock_selftest.py`'s arm 3, 16 Sep 2026 - the
defect was real and reasoning had not found it). So:

  `check_portable()` runs ANYWHERE, including the Mac this was written on, and
  covers the two things that do not need Windows to be wrong:

    1. THE ARITHMETIC. `winproc.foreign_delta` is `plib.ps1`'s
       `Measure-ForeignDelta` ported rule for rule, and that function is split
       out of its own sampler for exactly this reason - "it is exercised here
       over SYNTHETIC snapshots, which needs no Windows box at all". Same
       trick, same reason. The birth rule, the born-before-the-window rule, the
       pid-reuse rule and the cap are each driven directly.

    2. IMPORTABILITY IN THE WINDOWS CONFIGURATION. `pdrv.py` could not be
       imported on Windows at all, and the three blockers - `import fcntl`,
       `import resource` and `signal.SIGHUP` named inside a tuple - all fire at
       IMPORT time, before any test could reach them. Arm 4 below forces
       `os.name = "nt"` and makes `fcntl` and `resource` unimportable, then
       imports the module: a regression that puts either import back at module
       scope fails HERE, on a Mac, rather than on a box somebody had to book.

    3. AND THAT THE POSIX HALF DID NOT MOVE. The whole port is written under
       "new branches only", so arm 5 runs a real leg through the unchanged
       POSIX `run_leg` and asserts it still measures a child.

  `check_windows()` runs only on Windows and covers what only a real box can
  answer: the ctypes snapshot, the handle-based child accounting, and a rig
  lock take/release round trip against the very idiom `plib.ps1` uses.

A SKIPPED `check_windows()` IS REPORTED AS A SKIP AND NEVER AS A PASS. A green
line over zero arms is the failure mode this repo has a standing rule about,
and it is exactly what a port's selftest is most likely to present.

    python3 harness/pdrv_port_selftest.py
"""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import winproc  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    print("%-4s %s%s" % ("ok" if cond else "FAIL", name,
                         ("  - " + detail) if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def _row(ppid, name, cpu, start):
    return {"ppid": ppid, "name": name, "cpu": cpu, "start": start}


def check_portable():
    mine = 1000
    t0 = 100.0          # window start, unix epoch seconds
    window = 1.0
    cores = 8

    # --- arm 1: the plain delta, and our own tree excluded -----------------
    before = {mine: _row(1, "python.exe", 5.0, 10.0),
              2000: _row(1, "rival.exe", 100.0, 10.0),
              2001: _row(mine, "parfast.exe", 3.0, 10.0)}
    after = {mine: _row(1, "python.exe", 5.5, 10.0),
             2000: _row(1, "rival.exe", 100.5, 10.0),
             2001: _row(mine, "parfast.exe", 4.0, 10.0)}
    total, top = winproc.foreign_delta(before, after, window, t0, cores, mine)
    check("delta: foreign 0.5 s in 1 s reads 50% of one core", total == 50.0,
          "got %r" % total)
    check("delta: our own child is excluded",
          [t[1] for t in top] == [2000], "top=%r" % (top,))

    # --- arm 2: a pid absent from `before` --------------------------------
    # Born INSIDE the window -> charged in full. This is the case the rule
    # exists for: a neighbouring round's freshly spawned parfast.
    after_born = dict(after)
    after_born[3000] = _row(1, "parfast.exe", 0.4, t0 + 0.5)
    total, _ = winproc.foreign_delta(before, after_born, window, t0, cores, mine)
    check("delta: a process BORN in the window is charged in full",
          total == 90.0, "got %r" % total)

    # Born BEFORE the window but missing from `before` -> charged ZERO. This
    # is the spike source `Measure-ForeignDelta`'s header measured at 25-544%
    # of a core on an idle box.
    after_old = dict(after)
    after_old[3001] = _row(1, "MsMpEng.exe", 9999.0, 10.0)
    total, _ = winproc.foreign_delta(before, after_old, window, t0, cores, mine)
    check("delta: a pre-window process missing from `before` is charged ZERO",
          total == 50.0, "got %r" % total)

    # Start time unreadable -> charged zero, same reasoning.
    after_nostart = dict(after)
    after_nostart[3002] = _row(1, "?", 9999.0, None)
    total, _ = winproc.foreign_delta(before, after_nostart, window, t0, cores, mine)
    check("delta: an unreadable start time is charged ZERO", total == 50.0,
          "got %r" % total)

    # --- arm 3: pid reuse is a birth, not a delta -------------------------
    # Same pid, different start time, is a DIFFERENT process: its predecessor's
    # total is not a before reading for it.
    before_reuse = dict(before)
    before_reuse[4000] = _row(1, "old.exe", 500.0, 10.0)
    after_reuse = dict(after)
    after_reuse[4000] = _row(1, "new.exe", 0.25, t0 + 0.25)
    total, _ = winproc.foreign_delta(before_reuse, after_reuse, window, t0, cores, mine)
    check("delta: a recycled pid is a birth, never a negative delta",
          total == 75.0, "got %r" % total)

    # A recycled pid whose replacement started BEFORE the window is charged
    # zero rather than its predecessor's whole lifetime.
    after_reuse2 = dict(after)
    after_reuse2[4000] = _row(1, "new.exe", 900.0, 50.0)
    total, _ = winproc.foreign_delta(before_reuse, after_reuse2, window, t0, cores, mine)
    check("delta: a recycled pid from before the window is charged ZERO",
          total == 50.0, "got %r" % total)

    # The cap: a newborn cannot have burned more than window x cores.
    after_cap = dict(after)
    after_cap[5000] = _row(1, "impossible.exe", 1e9, t0 + 0.1)
    total, _ = winproc.foreign_delta(after_cap and before, after_cap, window, t0, cores, mine)
    check("delta: a newborn is clamped at window x cores",
          total == 50.0 + cores * 100.0, "got %r" % total)

    check("delta: a non-positive window refuses rather than dividing",
          winproc.foreign_delta(before, after, 0.0, t0, cores, mine)[0] == -1.0)

    # --- own_tree ---------------------------------------------------------
    snap = {1: _row(0, "init", 0.0, 1.0),
            mine: _row(1, "python", 0.0, 10.0),
            2001: _row(mine, "parfast", 0.0, 11.0),
            2002: _row(2001, "grandchild", 0.0, 12.0),
            2003: _row(1, "stranger", 0.0, 11.0)}
    tree = winproc.own_tree(snap, mine)
    check("own_tree: self, child and grandchild, and nothing else",
          tree == {mine, 2001, 2002}, "got %r" % (tree,))
    # A recycled pid naming us as a parent but predating us must NOT be adopted
    # into our tree, or it drops out of the foreign reading for free.
    snap_recycled = dict(snap)
    snap_recycled[2004] = _row(mine, "recycled", 0.0, 1.0)
    check("own_tree: a child older than its claimed parent is not adopted",
          2004 not in winproc.own_tree(snap_recycled, mine))

    # --- arm 4: pdrv imports in the WINDOWS configuration, on this box -----
    probe = os.path.join(HERE, "pdrv_port_selftest.py")
    code = (
        # Everything os.name-sensitive is imported BEFORE the name is
        # forced, or `shutil` takes its Windows branch and dies on
        # `import nt`. That is the stdlib noticing the lie, not a defect in
        # the port - and it is why this arm blocks fcntl/resource rather than
        # simply trusting `os.name`.
        "import os, sys, importlib.abc, importlib.machinery\n"
        "import shutil, platform, socket, subprocess, signal, tempfile\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name in ('fcntl', 'resource'):\n"
        "            raise ImportError('blocked by the selftest: %s' % name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "os.name = 'nt'\n"
        "sys.path.insert(0, __HERE__)\n"
        "import pdrv\n"
        "assert pdrv.IS_WIN, 'IS_WIN did not follow os.name'\n"
        "assert pdrv.fcntl is None and pdrv.resource is None\n"
        "print('IMPORTED-AS-WINDOWS')\n").replace("__HERE__", repr(HERE))
    del probe
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    check("pdrv imports with os.name='nt' and fcntl/resource unavailable",
          "IMPORTED-AS-WINDOWS" in res.stdout,
          (res.stdout + res.stderr).strip()[-600:])

    # --- arm 5: the POSIX half still measures a child ----------------------
    if os.name == "nt":
        print("skip POSIX run_leg arm - this box is Windows")
        return
    import pdrv  # noqa: E402 - after the sys.path line at the top
    # THE QUIET GATE IS DISABLED FOR THIS ARM, AND ONLY FOR IT. `run_leg`
    # refuses to run on a box carrying somebody else's load, which is exactly
    # right for a leg whose WALL is going to be published and exactly wrong
    # for a test of the plumbing: this arm asserts that a child is measured at
    # all, never how fast it was, and a dev Mac running nine lanes is never
    # going to be quiet. Nothing here reads a timing.
    pdrv.FOREIGN_CPU_CEILING_FRAC = 1e9
    pdrv.PER_CORE_CEILING_PCT = 1e9
    pdrv.QUIET_TRIES = 0
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "leg")
        rec = pdrv.run_leg(sys.executable,
                           ["-c", "x=0\nfor i in range(4000000): x+=i\nprint(x)"],
                           d, base)
        check("POSIX run_leg: rc 0", rec["rc"] == 0, repr(rec))
        check("POSIX run_leg: measures child CPU", rec["cpu"] > 0.0, repr(rec))
        check("POSIX run_leg: measures a peak", rec["peak_mb"] > 0.0, repr(rec))
        check("POSIX run_leg: wall is positive", rec["wall"] > 0.0, repr(rec))
        check("POSIX run_leg: steal is n/a or a number, never a bare 0 on mac",
              rec["steal_pct"] == "n/a" or isinstance(rec["steal_pct"], float),
              repr(rec["steal_pct"]))
        pdrv.box_facts()
        pdrv.rig_vol_facts(os.path.join(d, "fixture"))
        check("box_facts and rig_vol_facts run without raising", True)


def check_windows():
    """The arms that need a real Windows box. See the module docstring."""
    if os.name != "nt":
        print("SKIP check_windows - not a Windows box (%s). The ctypes "
              "snapshot, the handle-based child accounting and the rig lock "
              "round trip are UNPROVEN until this runs on windows-gaming-pc-b or amd-ryzen-9800x3d."
              % sys.platform)
        return False
    import pdrv  # noqa: E402
    # Same as the POSIX arm: this tests plumbing, not timing. See there.
    pdrv.FOREIGN_CPU_CEILING_FRAC = 1e9
    pdrv.PER_CORE_CEILING_PCT = 1e9
    pdrv.QUIET_TRIES = 0
    check("winproc.available()", winproc.available())
    snap = winproc.snapshot()
    check("snapshot: non-empty", len(snap) > 5, "got %d" % len(snap))
    check("snapshot: names this process", os.getpid() in snap)
    if os.getpid() in snap:
        check("snapshot: our own cpu time is positive",
              snap[os.getpid()]["cpu"] > 0.0, repr(snap[os.getpid()]))
        check("snapshot: our own start time is in the past",
              0 < snap[os.getpid()]["start"] <= time.time() + 1,
              repr(snap[os.getpid()]))
    total, _top = winproc.foreign_cpu_window(1.0)
    check("foreign_cpu_window: a plausible reading", -1.0 <= total < 100.0 * (os.cpu_count() or 1) * 2,
          "got %r" % total)

    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "leg")
        rec = pdrv.run_leg(sys.executable,
                           ["-c", "x=0\nfor i in range(4000000): x+=i\nprint(x)"],
                           d, base)
        check("win run_leg: rc 0", rec["rc"] == 0, repr(rec))
        check("win run_leg: measures child CPU off the handle", rec["cpu"] > 0.0, repr(rec))
        check("win run_leg: measures a peak working set", rec["peak_mb"] > 0.0, repr(rec))
        check("win run_leg: steal is n/a on bare metal, never 0.0",
              rec["steal_pct"] == "n/a", repr(rec["steal_pct"]))
        check("win run_leg: the child's stdout reached the log",
              os.path.getsize(base + ".out") > 0)

        # The rig lock, over a TEMP path - never the live ~/.parfast-rig.lock,
        # which may be held by somebody's round right now.
        lock = os.path.join(d, "rig.lock")
        a = pdrv.RigLock("selftest-a", lock_path=lock)
        a.take()
        check("win rig lock: the identity line names us",
              ("pid=%d" % os.getpid()) in open(lock).read(), open(lock).read())
        # WHAT THIS ARM ACTUALLY PROVES, WHICH IS NOT WHAT ITS NAME SUGGESTS.
        # Both takers are in THIS process, so `riglock_state` correctly reads
        # the identity line as naming US and returns `orphan` - "our own
        # leftover" - NOT `held`. The refusal that follows therefore comes from
        # the OS refusing to delete a file our own handle still has open
        # (WinError 32), which is the FILE_SHARE_DELETE property the whole
        # Windows arm rests on, and not from the live-holder rule. That is
        # worth having and is exactly the distinction
        # `windows_rig_lock_selftest.py` draws for `ladder.RigLock`. The
        # live-holder rule is proved separately, across processes, below.
        b = pdrv.RigLock("selftest-b", lock_path=lock)
        try:
            b.take()
            check("win rig lock: a second in-process taker is refused", False,
                  "the second take() succeeded")
        except SystemExit as exc:
            check("win rig lock: a second in-process taker exits 17 (this arm "
                  "proves the delete refusal, not the live-holder rule)",
                  exc.code == 17, "exit code %r" % (exc.code,))
        check("win rig lock: the holder's identity line survives the refusal",
              ("pid=%d" % os.getpid()) in open(lock).read())

        # THE LIVE-HOLDER RULE, ACROSS PROCESSES - the arm that matters, and
        # the one no amount of reasoning found the `_win_pid_alive` defect in
        # on 16 Sep 2026. A SEPARATE python process must be refused while we
        # hold the lock, and its refusal must leave our identity line alone.
        taker = (
            "import os, sys\n"
            "sys.path.insert(0, __HERE__)\n"
            "import pdrv\n"
            "try:\n"
            "    pdrv.RigLock('foreign', lock_path=__LOCK__).take()\n"
            "except SystemExit as e:\n"
            "    print('REFUSED-%s' % e.code); raise SystemExit(0)\n"
            "print('TOOK-IT')\n"
        ).replace("__HERE__", repr(HERE)).replace("__LOCK__", repr(lock))
        res = subprocess.run([sys.executable, "-c", taker],
                             capture_output=True, text=True)
        check("win rig lock: a FOREIGN process is refused while we hold it",
              "REFUSED-17" in res.stdout,
              (res.stdout + res.stderr).strip()[-400:])
        check("win rig lock: the foreign refusal left our identity intact",
              ("pid=%d" % os.getpid()) in open(lock).read(), open(lock).read())
        a.release()
        check("win rig lock: release removes the file", not os.path.exists(lock))
        c = pdrv.RigLock("selftest-c", lock_path=lock)
        c.take()
        check("win rig lock: a fresh taker wins after the handover", True)
        c.release()
    return True


if __name__ == "__main__":
    check_portable()
    ran_windows = check_windows()
    print("---")
    if FAILURES:
        print("FAILED %d: %s" % (len(FAILURES), ", ".join(FAILURES)))
        sys.exit(1)
    print("all arms passed%s" % ("" if ran_windows else
                                 " (the Windows-only arms were SKIPPED - this is "
                                 "NOT a verdict on a Windows box)"))
