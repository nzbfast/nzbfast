#!/usr/bin/env python3
"""anonscrub.py - anonymity scrub for a generated corpus tree.

    ./anonscrub.py <dir-or-file> [...]

The corpus is published verbatim (posted to a public group, NZBs and
list document alongside), and the generated trees live OUTSIDE the
repo's leak-check manifest - "0 public files clean" from that gate says
nothing about them. This scans them directly, against the same pattern
list every other leak gate reads (packaging/private-patterns.txt in the
private repo; the file is deliberately absent from the public tree, and
this script REFUSES to pass rather than scanning against nothing).

Region rule, learned the hard way by the site publish gate: the FULL
pattern list runs over text bytes and over every file PATH; raw binary
bytes (urandom payloads, PAR2 packets, archives) get only the STRONG
patterns - the `decompressed-only` block's three-character names hit
compressed entropy by chance, and a refusal over chance bytes is how a
leak gate gets loosened. A PAR2 FileDesc name or creator string is
ASCII inside binary, which the strong set still sees.

Exit 0 only when every file scanned clean; every hit is printed with
its file and the pattern that fired.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PATTERNS = os.path.join(HERE, "..", "..", "packaging", "private-patterns.txt")


def die(msg):
    print(f"[anonscrub] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def load_patterns():
    if not os.path.exists(PATTERNS):
        die(
            "packaging/private-patterns.txt not found - this scrub only "
            "runs in the private repo (it must never pass by scanning "
            "against nothing)"
        )
    full, strong = [], []
    weak = False
    for line in open(PATTERNS, encoding="utf-8"):
        s = line.strip()
        if s == "# ---- BEGIN decompressed-only ----":
            weak = True
            continue
        if s == "# ---- END decompressed-only ----":
            weak = False
            continue
        if not s or s.startswith("#"):
            continue
        rx = re.compile(s.encode())
        full.append((s, rx))
        if not weak:
            strong.append((s, rx))
    if not full or not strong:
        die("pattern list parsed empty - refusing to certify anything")
    return full, strong


def is_text(data):
    if b"\0" in data[:65536]:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def main():
    roots = sys.argv[1:]
    if not roots:
        sys.exit(__doc__)
    full, strong = load_patterns()
    # (file path, path-as-published): the path arm judges the path
    # RELATIVE to the scanned root - the published tree's own layout -
    # never the invocation path, which on this machine carries the
    # checkout location (an absolute root would false-hit the home
    # directory patterns about where the scan RAN, not what ships).
    files = []
    for r in roots:
        if os.path.isfile(r):
            files.append((r, os.path.basename(r)))
        elif os.path.isdir(r):
            for root, _dirs, names in os.walk(r):
                for n in names:
                    p = os.path.join(root, n)
                    files.append((p, os.path.relpath(p, os.path.dirname(r) or ".")))
        else:
            die(f"no such path: {r}")
    if not files:
        die("nothing to scan")
    hits = 0
    text_n = bin_n = 0
    for p, shipped in sorted(files):
        rel = shipped.encode()
        for pat, rx in full:
            if rx.search(rel):
                print(f"[anonscrub] HIT (path): {p}: {pat}")
                hits += 1
        data = open(p, "rb").read()
        if is_text(data):
            text_n += 1
            plist = full
            kind = "text"
        else:
            bin_n += 1
            plist = strong
            kind = "binary"
        for pat, rx in plist:
            if rx.search(data):
                print(f"[anonscrub] HIT ({kind}): {p}: {pat}")
                hits += 1
    if hits:
        die(f"{hits} hit(s) across {len(files)} file(s) - fix the CONTENT, never the list")
    print(
        f"[anonscrub] clean: {len(files)} file(s) ({text_n} text with the "
        f"full list, {bin_n} binary with the strong list), "
        f"{len(full)} pattern(s)"
    )


if __name__ == "__main__":
    main()
