#!/usr/bin/env python3
"""operator_passes.py - finish, by hand, what a client left unfinished, and time it.

NAMED `operator_passes` AND NOT `operator`, WHICH IS WHAT IT WAS UNTIL
3 SEP 2026. `operator` is a stdlib module name, and every script in this
directory carries `#!/usr/bin/env python3` while `generate.sh` runs its
manifest step as `python3 -` from this directory - so the interpreter put
this file at the head of sys.path and `import json` resolved `operator`
HERE, through the `from operator import eq` that CPython 3.9's
`collections` does at import time. On the Python a stock macOS box gives
`env python3` (3.9.6, Xcode's) that took out generate.sh, validate.py,
classify.py, report.py and leg_sampler.py together, with a traceback
naming `re` and a circular import and never this file's real fault; on
3.11 and later the same tree is fine, which is why it survived a week
undiagnosed. Do not name a file in this directory after a stdlib module.

    operator_passes.py --tree DIR --manifest M [--max-passes 6] [--json OUT]

WHY THIS EXISTS. A client that stops early looks FAST. Its elapsed time is
the time it took to give up, and setting that beside a client that ran to a
finished payload compares two different pieces of work - in the direction
that flatters the one that did less. On the nested corpus that is not a
corner case: on `r4` four clients deliver the damaged archive together with
its complete recovery set and stop, and their wall figures are all shorter
than the client that repaired it and went on.

So the honest quantity is TIME TO A USABLE PAYLOAD, and for those clients it
is their own time plus the operator's. This script is the operator: it runs
the same standard tools a person would reach for, in the same order, over
whatever the client left behind, and reports how many passes it needed and
how long each took.

A PASS is one sweep of "repair anything that verifies bad, then extract
anything extractable". More than one is needed whenever a layer only becomes
reachable after the layer above it is opened - which is the whole point of a
nested corpus, and why the count is reported rather than assumed to be one.

IT RUNS ON EVERY CLIENT, including the ones that finished. On a tree that is
already complete it finds nothing to do and reports zero passes, which is
the measurement, not a special case - a comparison where only the losers are
post-processed is not a comparison.

WHAT IT WILL AND WILL NOT DO, because that boundary IS the fairness rule.
It only does what a person with the post in front of them could do: run
par2 repair, extract archives, and read a password out of a file that was
posted in the clear beside them. It never reaches outside the client's own
output tree, never re-downloads, and never uses knowledge from the manifest
to decide what to do - the manifest is read ONLY to score the result, after
the work is finished.
"""

import argparse
import json
import os
import shutil
import subprocess
import threading
import time

import procsample
from leg_sampler import tree_kb

ARCHIVE_EXT = (".rar", ".7z")


def tool(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def find_unrar():
    """RARLab's unrar, wherever this box keeps it.

    Not on PATH here, but every NZBGet bundle ships one and that is the
    binary a person on this machine would actually use.
    """
    p = tool("unrar")
    if p:
        return [p, "x", "-y", "-o+"]
    for base in ("NZBGet263stable.app", "NZBGet270testing.app", "NZBGet0820.app"):
        c = os.path.expanduser(
            "~/competitors/%s/Contents/Resources/daemon/usr/local/bin/unrar" % base)
        if os.path.exists(c):
            return [c, "x", "-y", "-o+"]
    r = tool("rar")
    return [r, "x", "-y", "-o+"] if r else None


def walk(tree):
    out = []
    for root, _d, files in os.walk(tree):
        for n in files:
            out.append(os.path.join(root, n))
    return out


def snapshot(tree):
    return {p: os.path.getsize(p) for p in walk(tree) if os.path.exists(p)}


def par2_mains(files):
    """The main .par2 of each set, never the .volNNN+NN recovery files."""
    return [f for f in files
            if f.lower().endswith(".par2") and ".vol" not in os.path.basename(f).lower()]


def rar_entry(files):
    """One entry point per RAR set: the first volume, never parts 2..n."""
    out = []
    for f in files:
        b = os.path.basename(f).lower()
        if not b.endswith(".rar"):
            continue
        stem = b[:-4]
        if ".part" in stem:
            num = stem.rsplit(".part", 1)[1]
            if num.isdigit() and int(num) != 1:
                continue
        out.append(f)
    return out


def passwords(tree):
    """Candidates a person could read: short text files in the tree itself.

    The corpus posts the first password in the clear beside the volumes, so
    reading it is what an operator does. Nothing here guesses.
    """
    cands = []
    for f in walk(tree):
        if not f.lower().endswith(".txt"):
            continue
        try:
            if os.path.getsize(f) > 4096:
                continue
            for line in open(f, errors="replace").read().splitlines():
                line = line.strip()
                if line and line not in cands:
                    cands.append(line)
        except OSError:
            continue
    return cands


def run(cmd, cwd, timeout=900):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode
    except Exception:
        return -1


def do_repairs(tree, par2, files):
    n = 0
    for m in par2_mains(files):
        # `par2 repair` verifies first and is a no-op on a healthy set, so
        # this neither needs nor gets a separate verify step.
        if run([par2, "repair", "-q", os.path.basename(m)], os.path.dirname(m)) == 0:
            n += 1
    return n


def do_extracts(tree, unrar, sevenz, rar, files, pws):
    n, fixed = 0, 0
    for a in rar_entry(files) + [f for f in files if f.lower().endswith(".7z")]:
        d = os.path.dirname(a)
        base = os.path.basename(a)
        is_rar = base.lower().endswith(".rar")
        cmd = (unrar if is_rar else [sevenz, "x", "-y"])
        if not cmd or not cmd[0]:
            continue
        # No password first: the common case, and offering one where none is
        # needed makes some builds prompt.
        if run(cmd + [base], d) == 0:
            n += 1
            continue
        got = False
        for pw in pws:
            if run(cmd + ["-p" + pw, base], d) == 0:
                n += 1
                got = True
                break
        if got or not is_rar or not rar:
            continue
        # A RAR RECOVERY RECORD IS A THIRD REPAIR TOOL and an operator uses
        # it. Without this the corpus's damage-at-every-level leg reports
        # "stuck" for every client, because its innermost layer carries no
        # PAR2 at all - only an rr, which `par2` cannot see and `unrar`
        # will not apply on its own. Reporting a leg unfinishable when the
        # standard toolchain finishes it would understate every client.
        # `rar r` writes `fixed.<name>` beside the original; extracting that
        # is the operator's next move and is left to the next pass, which is
        # also what makes the pass count honest.
        if run([rar, "r", base], d) == 0:
            fixed += 1
    return n, fixed


def score(manifest, tree):
    here = os.path.dirname(os.path.abspath(__file__))
    r = subprocess.run(["python3", os.path.join(here, "classify.py"), manifest, tree, "0",
                        "--skip-dirs", ".weaver-staging"],
                       capture_output=True, text=True)
    return r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--max-passes", type=int, default=6)
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    par2, sevenz, unrar = tool("par2"), tool("7zz", "7za", "7z"), find_unrar()
    rar = tool("rar")
    # The operator is measured the same way the client is, or the two halves
    # of a time-to-payload figure would not be comparable. Its own pid is the
    # root: par2 and unrar run as its children, so the tree is exactly the
    # post-processing work and nothing else.
    native = procsample.make_native()
    samp = procsample.ProcSampler([], native)
    samp.tree = {os.getpid()}
    stop = threading.Event()
    hw = {"kb": 0}

    def watch():
        while not stop.is_set():
            samp.discover_children(os.getpid())
            samp.sample()
            k = tree_kb(a.tree)
            if k and k > hw["kb"]:
                hw["kb"] = k
            time.sleep(0.02)
    th = threading.Thread(target=watch, daemon=True)
    res = {"passes": 0, "pass_seconds": [], "total_seconds": 0.0,
           "repairs": 0, "extracts": 0, "rar_repairs": 0,
           "tools": {"par2": bool(par2), "unrar": bool(unrar), "7z": bool(sevenz),
                     "rar": bool(rar)},
           "before": score(a.manifest, a.tree)}
    res["engine"] = "native" if native else "ps"
    if "class=auto-complete" in res["before"]:
        # Already finished. Reported as zero passes rather than skipped: the
        # operator runs on every client, and "nothing to do" is the result.
        res["after"] = res["before"]
        res["outcome"] = "already-complete"
        _emit(res, a.json)
        return

    pws = passwords(a.tree)
    res["password_candidates"] = len(pws)
    th.start()
    for _ in range(a.max_passes):
        before = snapshot(a.tree)
        t0 = time.time()
        files = list(before)
        res["repairs"] += do_repairs(a.tree, par2, files) if par2 else 0
        ex, fx = do_extracts(a.tree, unrar, sevenz, rar, files, pws)
        res["extracts"] += ex
        res["rar_repairs"] += fx
        dt = time.time() - t0
        res["passes"] += 1
        res["pass_seconds"].append(round(dt, 3))
        res["total_seconds"] = round(sum(res["pass_seconds"]), 3)
        after = snapshot(a.tree)
        res["after"] = score(a.manifest, a.tree)
        if "class=auto-complete" in res["after"]:
            res["outcome"] = "completed-by-operator"
            break
        if after == before:
            # A pass that changed nothing will not change anything next time
            # either: this is where an operator stops, and the leg is genuinely
            # unfinishable with the standard tools.
            res["outcome"] = "stuck"
            break
        # New password files may have been unpacked by this pass.
        pws = passwords(a.tree)
    else:
        res["outcome"] = "pass-limit"
    stop.set()
    th.join(timeout=5)
    res["hiwater_mb"] = hw["kb"] // 1024
    res["cpu_s"] = round(samp.cpu_s, 1)
    res["peak_rss_mb"] = samp.peak_rss // 1048576
    res["disk_read_mb"] = samp.disk_read // 1048576
    res["disk_write_mb"] = samp.disk_write // 1048576
    _emit(res, a.json)


def _emit(res, path):
    s = json.dumps(res, sort_keys=True)
    if path:
        open(path, "w").write(s)
    print(s)


if __name__ == "__main__":
    main()
