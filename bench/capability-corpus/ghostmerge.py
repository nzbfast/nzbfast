#!/usr/bin/env python3
"""ghostmerge.py - add GHOST files to a posted NZB (the par-only leg).

    ./ghostmerge.py <posted.nzb> <ghostdir> [--msgid-domain D] [--article-size N]

The a2-par-only capability leg wants every archive article MISSING
(430) while the posted PAR2 set carries 100% recovery data. On the
loopback rig nzbserve serves ghost/ as 430s natively; on real Usenet
the equivalent is an NZB that references articles nobody ever posted.
So: post ONLY the leg's post/ dir (`nzbfast post`), then run this to
append one <file> entry per ghost/ file - fresh random-hex message-ids
under the given domain (minted the same shape `nzbfast post` mints,
guaranteed unposted, so every server answers them 430/430-equivalent),
subjects in the standard yEnc convention, and per-segment byte counts
computed from the file's actual size at the same article size the post
run used.

Writes `<posted>.merged.nzb` beside the input (never in place), parses
the result back, and refuses to emit anything that does not survive a
structural re-read.
"""

import os
import re
import secrets
import sys
import xml.etree.ElementTree as ET


def die(msg):
    print(f"[ghostmerge] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def esc(s):
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def yenc_encoded_size(n, art):
    """Encoded size estimate per the yEnc overhead model: ~1.6% payload
    expansion for escaped bytes plus line breaks and the header/trailer
    lines. A hint for download schedulers, not a checksum - real NZBs
    vary here too."""
    if n == 0:
        return 64
    lines = (n + 127) // 128
    return int(n * 1.016) + 2 * lines + 120


def main():
    args = sys.argv[1:]
    domain = "nzbfast.invalid"
    art = 700_000
    pos = []
    while args:
        a = args.pop(0)
        if a == "--msgid-domain" and args:
            domain = args.pop(0)
        elif a == "--article-size" and args:
            art = int(args.pop(0))
        else:
            pos.append(a)
    if len(pos) != 2:
        sys.exit(__doc__)
    nzb_path, ghostdir = pos
    if not os.path.isdir(ghostdir):
        die(f"{ghostdir} is not a directory")
    ghosts = sorted(
        n for n in os.listdir(ghostdir)
        if not n.startswith(".") and os.path.isfile(os.path.join(ghostdir, n))
    )
    if not ghosts:
        die(f"{ghostdir} holds no ghost files")
    xml = open(nzb_path, encoding="utf-8").read()
    end = xml.rfind("</nzb>")
    if end < 0:
        die(f"{nzb_path} has no </nzb> close tag")
    # The group the post went to, reused verbatim for the ghost entries.
    m = re.search(r"<group>([^<]+)</group>", xml)
    if not m:
        die(f"{nzb_path} carries no <group> to reuse")
    group = m.group(1)

    add = []
    for name in ghosts:
        size = os.path.getsize(os.path.join(ghostdir, name))
        if size == 0:
            die(f"ghost {name} is empty - a 0-byte ghost describes nothing")
        parts = max(1, (size + art - 1) // art)
        add.append(
            f'<file poster="ghost@{esc(domain)}" date="0" '
            f'subject="&quot;{esc(name)}&quot; yEnc (1/{parts})">\n'
            f"<groups><group>{esc(group)}</group></groups>\n<segments>\n"
        )
        for part in range(1, parts + 1):
            seg = min(art, size - (part - 1) * art)
            mid = f"{secrets.token_hex(16)}@{domain}"
            add.append(
                f'<segment bytes="{yenc_encoded_size(seg, art)}" '
                f'number="{part}">{esc(mid)}</segment>\n'
            )
        add.append("</segments>\n</file>\n")
    merged = xml[:end] + "".join(add) + xml[end:]

    root = ET.fromstring(merged)
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    n_files = len(root.findall(f"{ns}file"))
    out = nzb_path + ".merged.nzb"
    with open(out, "w", encoding="utf-8") as f:
        f.write(merged)
    print(
        f"[ghostmerge] {out}: {n_files} file entries "
        f"({len(ghosts)} ghost file(s) added, ids under @{domain})"
    )


if __name__ == "__main__":
    main()
