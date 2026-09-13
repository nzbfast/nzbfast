#!/usr/bin/env python3
"""Build apps/parfast/windows/Parfast.App/Assets/parfast.ico from the SVG masters.

    python3 tools/make-icon.py            build and write
    python3 tools/make-icon.py --check    prove the committed bytes

WHY A SECOND SCRIPT AND NOT packaging/icon/make-ico.py. That one is nzbfast's,
its DERIVATIONS table is read by packaging/icon/derivations.py AND by
tools/icons-derived-gate.py, and the gate holds the recorded digests of nzbfast's
own masters. Adding parfast's rows to that table would put a second product's art
under a gate that exists to catch a stale nzbfast taskbar icon. So this script
does the same job for the GUI's icon, and REUSES the one piece worth reusing:
packaging/icon/rasterize.py, which is the only way to get a real alpha channel out
of a stock Mac (qlmanage flattens onto white; that file's header explains the
two-render recovery in full).

THE MASTERS ARE PLACEHOLDERS. apps/parfast/shared/icon/ is chip B's to own, and
when its master lands this script's SOURCES table should point at it and the two
files under Assets/ should go. That is a one-line change here, deliberately.

The small entries (16, 24, 32) are rasterized from the SMALL master rather than
downscaled from the large one, for the reason nzbfast's generator gives: at 16 px a
resample of a four-column grid is grey mush.

macOS only, like its model: qlmanage and sips. On Windows or Linux it refuses
rather than writing something wrong, and the committed .ico is what the build uses.
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS_ROOT = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(WINDOWS_ROOT)))
RASTERIZE = os.path.join(REPO_ROOT, "packaging", "icon", "rasterize.py")
OUT = os.path.join(WINDOWS_ROOT, "Parfast.App", "Assets", "parfast.ico")

LARGE = os.path.join(WINDOWS_ROOT, "Parfast.App", "Assets", "parfast-icon.svg")
SMALL = os.path.join(WINDOWS_ROOT, "Parfast.App", "Assets", "parfast-icon-small.svg")

# One row per .ico entry, in the order they are written.
SOURCES = [
    (SMALL, 16),
    (SMALL, 24),
    (SMALL, 32),
    (LARGE, 48),
    (LARGE, 64),
    (LARGE, 128),
    (LARGE, 256),
]


def build(td):
    """The .ico bytes: ICONDIR, one ICONDIRENTRY per row, then the PNGs."""
    datas = []
    for src, size in SOURCES:
        if not os.path.isfile(src):
            raise SystemExit(f"x {src} is missing")
        png = os.path.join(td, f"{size}.png")
        subprocess.run(["python3", RASTERIZE, src, str(size), png], check=True)
        with open(png, "rb") as f:
            datas.append(f.read())

    header = struct.pack("<HHH", 0, 1, len(SOURCES))
    entries = b""
    offset = 6 + 16 * len(SOURCES)
    for (_src, size), data in zip(SOURCES, datas):
        # 256 is written as 0: the width and height fields are one byte each.
        entries += struct.pack(
            "<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return header + entries + b"".join(datas)


def main(argv):
    check = argv == ["--check"]
    if argv and not check:
        raise SystemExit(__doc__)

    if sys.platform != "darwin":
        if check and os.path.isfile(OUT):
            print(f"- {os.path.relpath(OUT, WINDOWS_ROOT)} exists; "
                  "its bytes can only be proved on a mac (qlmanage).")
            return 0
        raise SystemExit(
            "x this generator needs macOS (qlmanage and sips). The .ico is "
            "committed, so a Windows build does not need to run it.")

    if not os.path.isfile(RASTERIZE):
        raise SystemExit(f"x {RASTERIZE} is missing; it is the alpha-correct rasterizer")

    with tempfile.TemporaryDirectory() as td:
        fresh = build(td)

    if check:
        if not os.path.isfile(OUT):
            raise SystemExit(f"x {OUT} has not been built")
        with open(OUT, "rb") as f:
            if f.read() != fresh:
                raise SystemExit(
                    f"x {os.path.relpath(OUT, WINDOWS_ROOT)} is stale. Rerun this "
                    "script; never hand-patch a generated file.")
        print(f"ok {os.path.relpath(OUT, WINDOWS_ROOT)} matches its masters "
              f"({len(SOURCES)} entries)")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(fresh)
    print(f"wrote {os.path.relpath(OUT, WINDOWS_ROOT)} "
          f"({len(fresh):,} bytes, {len(SOURCES)} entries: "
          f"{', '.join(str(s) for _m, s in SOURCES)})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
