#!/usr/bin/env python3
"""Build a .qpkg fixture, byte-for-byte the shape a QDK package has.

    [ installer shell script ][ control tar ][ data tar.gz ][ 100-byte trailer ]

The control tar holds exactly one member, itself a .tgz, which is why
the installer pipes `tar -xO | tar -xz`, and the script declares both of
the lengths a reader needs to find the boundaries. That is the shape
packaging/qnap/unpack-qpkg.sh splits and the one every gate that looks
inside a .qpkg depends on.

Shared rather than copied because two tests need it - the builder-identity
gate (packaging/tests/archive-identity.sh) and the macOS-metadata gate
(packaging/tests/qpkg-junk-gate.sh) - and this repo's per-box shell
scripts have twice rotted by being copy-paste descendants of each other.
Underscored file name so it can be imported; every other script here is
hyphenated and none of them is.

    import sys; sys.path.insert(0, "packaging/tests")
    from qpkg_fixture import build
    build("/tmp/x.qpkg", owner=(1001, 1001, "runner", "docker"))

    packaging/tests/qpkg_fixture.py out.qpkg        # or from a shell
"""

import io
import struct
import sys
import tarfile

PAYLOAD = b"nzbfast\n" * 64
# A REAL AppleDouble file, not just a file whose name starts with `._`:
# magic 00051607, version 2, 16 bytes of filler, one FinderInfo entry.
# bsdtar only consumes a `._name` member it can parse as one, and the
# consumption is the whole point - a fixture with junk bytes in it would
# survive extraction on the Mac and quietly stop demonstrating the trap.
APPLEDOUBLE = (struct.pack(">II", 0x00051607, 0x00020000) + b"\x00" * 16
               + struct.pack(">H", 1) + struct.pack(">III", 9, 38, 32)
               + b"\x00" * 32)
CLEAN = (0, 0, "", "")
ROOT = (0, 0, "root", "root")
# What the 1.1.3 .qpkg actually shipped, on every member of both inner tars.
RUNNER = (1001, 1001, "runner", "docker")
# scan-release-assets.sh refuses a .qpkg whose data archive holds no
# `nzbfast-*` binary - "it unpacked" is not proof the payload was reached -
# so the default data set has to satisfy that scanner too.
DATA_NAMES = ("./nzbfast.sh", "./nzbfast-x86_64")
CONTROL_NAMES = ("./qpkg.cfg",)


def _body(name):
    return APPLEDOUBLE if name.rsplit("/", 1)[-1].startswith("._") else PAYLOAD


def _member(name, owner):
    ti = tarfile.TarInfo(name)
    ti.size = len(_body(name))
    ti.uid, ti.gid, ti.uname, ti.gname = owner
    return ti


def _tar(names, owner, mode):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for n in names:
            t.addfile(_member(n, owner), io.BytesIO(_body(n)))
    return buf.getvalue()


def build(path, owner=ROOT, data_names=DATA_NAMES,
          control_names=CONTROL_NAMES, trailer=b"Q" * 100):
    """Write a .qpkg at `path`. Returns the bytes it wrote.

    `owner` is (uid, gid, uname, gname) applied to every member of both
    inner tars - the leak, when there is one. The tar that WRAPS the
    control .tgz always stays clean, so a checker that stops at the outer
    layer sees nothing and a fixture proves it went a layer down.
    """
    ctrl_inner = _tar(control_names, owner, "w:gz")
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w") as t:
        ti = tarfile.TarInfo("control.tar.gz")
        ti.size = len(ctrl_inner)
        ti.uid, ti.gid, ti.uname, ti.gname = CLEAN
        t.addfile(ti, io.BytesIO(ctrl_inner))
    ctrl = ctrl.getvalue()
    data = _tar(data_names, owner, "w:gz")
    kib = (len(data) + 1023) // 1024
    script = ("#!/bin/sh\n"
              "script_len=@@LEN@@\n"
              "offset=$(/usr/bin/expr $script_len + %d)\n"
              '/bin/dd if="${0}" bs=$offset skip=1 | /bin/cat | '
              "/bin/dd bs=1024 count=%d of=$_EXTRACT_DIR/data.tar.gz || exit 1\n"
              % (len(ctrl), kib))
    # script_len is the script's OWN length, so the placeholder has to be
    # replaced by a string of the same width to stay true - iterate to the
    # fixed point rather than guess the number of digits.
    n = len(script) - len("@@LEN@@") + len(str(len(script)))
    for _ in range(4):
        n = len(script.replace("@@LEN@@", str(n)))
    blob = script.replace("@@LEN@@", str(n)).encode() + ctrl + data + trailer
    with open(path, "wb") as fh:
        fh.write(blob)
    return blob


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        sys.exit(2)
    build(sys.argv[1])
