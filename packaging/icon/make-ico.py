#!/usr/bin/env python3
"""Build nzbfast.ico from the two SVG masters - stdlib only, rasterizing
through rasterize.py (qlmanage) and downscaling with macOS `sips`. Entries
are PNG-compressed (fine on Windows Vista+; we support Win10/11). Run from
anywhere:

    python3 packaging/icon/make-ico.py            build and record
    python3 packaging/icon/make-ico.py --check    prove the committed bytes

16/24/32 come from icon-small.svg (bolt alone) and everything larger from
icon-1024.png, itself rasterized from icon.svg (bolt plus slipstream) - an
.ico stores one image per size, which is exactly what that split is for.
Windows picks the entry matching the surface it is drawing, so the taskbar
and the alt-tab list each get art drawn for their size instead of a
downscale of the other one's.

Each small entry is rasterized at its own size rather than downscaled: at
16 px a resample smears the bolt's edges into the tile and the mark turns to
mush, which was the original complaint.

nzbfast.ico IS COMMITTED and it is what the Windows installer sets as the
executable's icon (packaging/windows/installer.iss), so a stale one is the
mark in the taskbar and the alt-tab list. tools/icons-derived-gate.py holds
the recorded digests of both masters on every branch push, and reads this
.ico's own entry table back to check that the sizes it carries are the sizes
DERIVATIONS below asks for - a container that quietly lost its 24 px entry
looks exactly like a healthy one from the outside. `--check` proves the
bytes and needs a mac.
"""
import os
import subprocess
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(HERE, "nzbfast.ico")

# DERIVATIONS - the table this script, packaging/icon/derivations.py and
# tools/icons-derived-gate.py all read. "<source> <output> <pixel size>",
# repo-relative, ONE ROW PER .ico ENTRY and in the order the entries are
# written. A .svg source is rasterized at that size; a .png source is
# downscaled from it with `sips`.
#
# The 48 px and up rows name icon-1024.png rather than icon.svg because
# that is literally what they are made from, and saying so is what makes
# the staleness chain work: edit icon.svg, and the gate reports
# icon-1024.png stale first, then this file the moment that raster is
# regenerated.
DERIVATIONS = """
packaging/icon/icon-small.svg    packaging/icon/nzbfast.ico     16
packaging/icon/icon-small.svg    packaging/icon/nzbfast.ico     24
packaging/icon/icon-small.svg    packaging/icon/nzbfast.ico     32
packaging/icon/icon-1024.png     packaging/icon/nzbfast.ico     48
packaging/icon/icon-1024.png     packaging/icon/nzbfast.ico     64
packaging/icon/icon-1024.png     packaging/icon/nzbfast.ico    128
packaging/icon/icon-1024.png     packaging/icon/nzbfast.ico    256
"""

# Importing a sibling would drop a __pycache__ directory into
# packaging/icon/, which is untracked, unwanted, and turns up in the next
# person's git status - the same trap packaging/qnap/make-icons.sh
# documents at its own import.
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
from derivations import parse_table  # noqa: E402  (needs HERE on the path)


def build(rows, td):
    """The .ico bytes: ICONDIR, one ICONDIRENTRY per row, then the PNGs.

    `parse_table` hands back a four-field row - the fourth is the
    TRANSFORM, which the second-generation tables use to say `grey`.
    Every row here is a plain scale, and the assert says so rather than
    scaling a row that asked for something else: a transform this
    generator silently ignored would put the wrong art in the Windows
    taskbar with every digest still matching.
    """
    datas = []
    for src, _out, size, transform in rows:
        if transform != "scale":
            raise SystemExit(
                f"\u2717 {src} at {size} px asks for transform {transform!r}; this "
                "generator only scales. Teach it the transform rather than "
                "dropping the column.")
        p = os.path.join(td, f"{size}.png")
        abs_src = os.path.join(ROOT, src)
        if not os.path.isfile(abs_src):
            raise SystemExit(f"✗ {src} is missing")
        if src.endswith(".svg"):
            subprocess.run(
                ["python3", os.path.join(HERE, "rasterize.py"), abs_src, str(size), p],
                check=True)
        else:
            subprocess.run(
                ["sips", "-z", str(size), str(size), abs_src, "--out", p],
                check=True, capture_output=True)
        with open(p, "rb") as f:
            datas.append(f.read())

    hdr = struct.pack("<HHH", 0, 1, len(rows))
    entries = b""
    off = 6 + 16 * len(rows)
    for (_src, _out, size, _transform), d in zip(rows, datas):
        # 256 is written as 0 - the width and height fields are one byte.
        entries += struct.pack(
            "<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(d), off)
        off += len(d)
    return hdr + entries + b"".join(datas)


def main(argv):
    check = False
    if argv == ["--check"]:
        check = True
    elif argv:
        print(f"usage: {sys.argv[0]} [--check]", file=sys.stderr)
        return 2

    rows = parse_table(DERIVATIONS_SOURCE, "packaging/icon/make-ico.py")
    outs = {out for _s, out, _z, _t in rows}
    if len(outs) != 1:
        raise SystemExit(f"✗ this generator writes one .ico; DERIVATIONS names {sorted(outs)}")

    with tempfile.TemporaryDirectory() as td:
        blob = build(rows, td)

    if check:
        if not os.path.isfile(OUT):
            print("✗ packaging/icon/nzbfast.ico is not committed", file=sys.stderr)
            return 1
        with open(OUT, "rb") as f:
            if f.read() != blob:
                print(
                    "✗ packaging/icon/nzbfast.ico differs from what this script produces now",
                    file=sys.stderr)
                print("    Rerun it with no arguments and commit what it wrote. Do NOT", file=sys.stderr)
                print("    hand-patch the .ico - the next run undoes it and says nothing.", file=sys.stderr)
                return 1
        rc = subprocess.run(
            ["python3", os.path.join(HERE, "derivations.py"), "check", "make-ico.py"]).returncode
        if rc:
            return 1
        print(f"✓ the committed .ico and its records match this generator "
              f"({len(rows)} entries)")
        return 0

    with open(OUT, "wb") as f:
        f.write(blob)
    print(f"wrote {OUT} ({len(blob)} bytes, sizes {[z for _s, _o, z in rows]})",
          flush=True)
    return subprocess.run(
        ["python3", os.path.join(HERE, "derivations.py"), "record", "make-ico.py"]).returncode


# The table is read out of this file's own text, exactly as the recorder and
# the gate read it - so a shape they cannot parse is a shape this script
# cannot build from either, rather than a disagreement nobody notices.
with open(os.path.abspath(__file__), encoding="utf-8") as _f:
    DERIVATIONS_SOURCE = _f.read()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
