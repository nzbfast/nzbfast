#!/usr/bin/env python3
"""validate.py - prove every generated leg is recoverable with stock tools.

    validate.py <legdir|tier-dir|corpus-root> ...

For each leg: copy post/ into <legdir>/.validate (ghost/ files stay
deleted - reconstructing them is the exercise), then run the full manual
recovery chain an expert operator would: par2 repair, unrar / 7z extract,
rar r for recovery-record archives, passwords from the manifest, repeated
until nothing new appears. Finally grade the result with classify.py; a
valid leg must classify auto-complete. Exit nonzero if any leg does not.

This is the corpus self-test, not a client benchmark: it proves the
archives, the damage, and the recovery data are all consistent, so a
client's manual-intervention or fail class is the client's result, not a
broken fixture.
"""

import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_ROUNDS = 12
SEVENZ = os.environ.get("SEVENZ") or next(
    (c for c in ("7zz", "7z", "7za") if shutil.which(c)), "7zz"
)


def run(cmd, cwd):
    return subprocess.run(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )


def is_entry_archive(name):
    """First volume of a set, a solo rar, a 7z, a split 7z or a zip -
    something to extract.

    THE .zip AND .7z.001 ARMS WERE MISSING UNTIL 3 SEP 2026, and the two
    legs that need them (r5-zip, r6-7z-split) had been graded BROKEN by
    this file since they landed - a self-test reporting that the corpus
    was inconsistent when what was short was its own reach. Both legs
    hand-extract clean with one 7zz call. A leg added to generate.sh
    whose container this predicate cannot name is reported as a broken
    FIXTURE, which is the most expensive way for this file to be wrong:
    it accuses the thing it exists to vouch for. Widen this and
    try_extract together whenever a new container joins the corpus.
    """
    low = name.lower()
    if low.endswith(".7z") or low.endswith(".zip"):
        return True
    # A split 7z is `stem.7z.001`, `.002`, ...; only volume one is an
    # entry, and 7zz picks up the rest of the set from the directory.
    if re.search(r"\.7z\.0*1$", low):
        return True
    if not low.endswith(".rar"):
        return False
    m = re.search(r"\.part(\d+)\.rar$", low)
    return m is None or int(m.group(1)) == 1


def passwords(manifest):
    pw = manifest.get("passwords") or {}
    return [None] + [v for _k, v in sorted(pw.items())]


def try_extract(tmp, name, pws):
    """Extract one archive with unrar/7zz, trying each password. Returns
    True on success."""
    for pw in pws:
        # RAR goes to unrar; everything else this file recognises - 7z,
        # split 7z, zip - goes to 7-Zip, which reads all three.
        if name.lower().endswith(".rar"):
            cmd = ["unrar", "x", "-y", "-o+", "-idq", "-p" + (pw or "-"), name]
        else:
            cmd = [SEVENZ, "x", "-y", "-bso0", "-bsp0"]
            cmd.append("-p" + (pw or ""))
            cmd.append(name)
        if run(cmd, tmp).returncode == 0:
            return True
    return False


def validate_leg(legdir):
    import json

    manifest = json.load(open(os.path.join(legdir, "manifest.json")))
    leg = manifest["leg"]
    tmp = os.path.join(legdir, ".validate")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    post = os.path.join(legdir, "post")
    for n in os.listdir(post):
        if not n.startswith("."):
            shutil.copy2(os.path.join(post, n), tmp)

    pws = passwords(manifest)
    extracted, repaired_par2, repaired_rr = set(), set(), set()
    for _round in range(MAX_ROUNDS):
        progressed = False
        # PAR2 repair pass: every index par2 not yet run this state.
        for n in sorted(os.listdir(tmp)):
            if n.lower().endswith(".par2") and ".vol" not in n.lower():
                if n in repaired_par2:
                    continue
                r = run(["par2", "repair", "-q", "-q", n], tmp)
                if r.returncode == 0:
                    repaired_par2.add(n)
                    progressed = True
        # Extraction pass. An archive that already went through rar r is
        # never retried: retrying would re-extract its damaged payload
        # over the good bytes the fixed.* copy produced (-o+ overwrite).
        for n in sorted(os.listdir(tmp)):
            if n in extracted or n in repaired_rr or not is_entry_archive(n):
                continue
            if try_extract(tmp, n, pws):
                extracted.add(n)
                progressed = True
            elif n.lower().endswith(".rar") and n not in repaired_rr:
                # Recovery-record repair: rar r writes fixed.<name> (RR)
                # or rebuilt.<name>; the fixed copy is picked up next
                # round as a fresh entry archive.
                run(["rar", "r", "-idq", "-y", n], tmp)
                repaired_rr.add(n)
                if any(f.startswith(("fixed.", "rebuilt.")) for f in os.listdir(tmp)):
                    progressed = True
        if not progressed:
            break

    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "classify.py"),
         os.path.join(legdir, "manifest.json"), tmp, "0"],
        stdout=subprocess.PIPE, text=True,
    )
    line = r.stdout.strip()
    ok = "class=auto-complete" in line
    print(f"VALIDATE {leg} {'OK' if ok else 'BROKEN'} {line}")
    shutil.rmtree(tmp, ignore_errors=True)
    return ok


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    legs = []
    for root in sys.argv[1:]:
        if os.path.isfile(os.path.join(root, "manifest.json")):
            legs.append(root)
        else:
            for dirpath, _d, files in os.walk(root):
                if "manifest.json" in files:
                    legs.append(dirpath)
    if not legs:
        sys.exit("no legs found")
    bad = [l for l in sorted(legs) if not validate_leg(l)]
    if bad:
        sys.exit(f"BROKEN legs: {', '.join(os.path.basename(b) for b in bad)}")
    print(f"all {len(legs)} leg(s) validate")


if __name__ == "__main__":
    main()
