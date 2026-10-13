#!/usr/bin/env python3
"""Write the Windows portable zip, the same on every host.

    packaging/windows/make-portable-zip.py <out.zip> <inner-dir> <file> [<file> ...]
    packaging/windows/make-portable-zip.py --selftest

Every file lands flat under `<inner-dir>/` (the x64 zip's is
`nzbfast-windows/`, which make-pkg-manifests.sh, the Scoop manifest and
av-scan.sh all read). It replaces `zip -r -X` on the release Mac and
`Compress-Archive` on a Windows runner, and exists because neither of
those writes the same bytes twice:

- entry times come from SOURCE_DATE_EPOCH when it is set (the
  provenance workflow pins it to the tag's commit time), not the wall
  clock, so a rebuild of the tag can match;
- names use `/` (Windows PowerShell 5.1's Compress-Archive writes `\\`,
  which APPNOTE 4.4.17.1 forbids and unix unzip turns into one file
  named `nzbfast-windows\\nzbfast.exe` - see release.yml's arm64 job);
- entries carry unix modes and no owner, which is what the v1.7.1 zips
  built by the Mac's Info-ZIP carried, so an unzip on Linux or macOS keeps
  the exec bits it always had. A PROGRAM is 0755 and everything else
  0644, and a program is decided by NAME, never by the file's mode on
  disk: an `.exe`, a `.command`, or a name with no extension (the macOS
  zip's `nzbfast`). Asking the disk would give a different answer on a
  Windows runner, where Python reports `.bat` as executable, and v1.7.1
  shipped `Start nzbfast.bat` as 0644.

There is no uid/gid field in a zip, so there is nothing for
packaging/check-archive-identity.py to find; it runs over the output
anyway, because "the format cannot carry it" is an inference.
"""

import os
import sys
import tempfile
import time
import zipfile

DIR_MODE = 0o40755
EXE_MODE = 0o100755
FILE_MODE = 0o100644


def stamp():
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or 0)
    # The zip format cannot store a time before 1980.
    epoch = max(epoch, 315532800)
    return time.gmtime(epoch)[:6]


def info(name, mode, when):
    zi = zipfile.ZipInfo(name, date_time=when)
    zi.create_system = 3  # unix, so external_attr's high half is a mode
    zi.external_attr = (mode << 16) | (0x10 if mode == DIR_MODE else 0)
    zi.compress_type = zipfile.ZIP_STORED if mode == DIR_MODE else zipfile.ZIP_DEFLATED
    return zi


def is_program(name):
    root, ext = os.path.splitext(name)
    return ext.lower() in (".exe", ".command") or (ext == "" and not root.startswith("."))


def write(out, inner, files):
    if not inner or "/" in inner or "\\" in inner:
        raise SystemExit("inner directory must be one plain name, got %r" % inner)
    names = [os.path.basename(f) for f in files]
    if len(set(names)) != len(names):
        raise SystemExit("two inputs share a file name: %s" % names)
    when = stamp()
    with zipfile.ZipFile(out, "w", compresslevel=9) as z:
        z.writestr(info(inner + "/", DIR_MODE, when), b"")
        for f, name in sorted(zip(files, names), key=lambda p: p[1]):
            mode = EXE_MODE if is_program(name) else FILE_MODE
            with open(f, "rb") as src:
                z.writestr(info("%s/%s" % (inner, name), mode, when), src.read())
    print("%s: %d file(s) under %s/" % (out, len(files), inner))


def selftest():
    ok = True
    with tempfile.TemporaryDirectory() as d:
        a = os.path.join(d, "nzbfast.exe")
        b = os.path.join(d, "Start nzbfast.bat")
        open(a, "wb").write(b"MZ" + b"\0" * 64)
        open(b, "wb").write(b"@echo off\r\n")
        os.environ["SOURCE_DATE_EPOCH"] = "1790000000"
        z1, z2 = os.path.join(d, "1.zip"), os.path.join(d, "2.zip")
        write(z1, "nzbfast-windows", [a, b])
        os.utime(a, (1, 1))  # a changed mtime must not change the bytes
        write(z2, "nzbfast-windows", [b, a])
        same = open(z1, "rb").read() == open(z2, "rb").read()
        print("%s same inputs, any order, any mtime: identical bytes" % ("ok  " if same else "FAIL"))
        ok &= same
        z = zipfile.ZipFile(z1)
        modes = {i.filename: i.external_attr >> 16 for i in z.infolist()}
        progs = (is_program("nzbfast"), is_program("Start nzbfast.command"),
                 is_program("Start nzbfast.bat"), is_program("MANUAL.html"))
        good = progs == (True, True, False, False)
        print("%s program-by-name rule" % ("ok  " if good else "FAIL %r" % (progs,)))
        ok &= good
        want = {"nzbfast-windows/": DIR_MODE,
                "nzbfast-windows/Start nzbfast.bat": FILE_MODE,
                "nzbfast-windows/nzbfast.exe": EXE_MODE}
        print("%s names and modes" % ("ok  " if modes == want else "FAIL %r" % modes))
        ok &= modes == want
        dates = {i.date_time for i in z.infolist()}
        good = dates == {time.gmtime(1790000000)[:6]}
        print("%s entry times come from SOURCE_DATE_EPOCH" % ("ok  " if good else "FAIL"))
        ok &= good
        try:
            write(os.path.join(d, "3.zip"), "a/b", [a])
            print("FAIL a nested inner directory was accepted")
            ok = False
        except SystemExit:
            print("ok   a nested inner directory is refused")
    print("make-portable-zip selftest: %s" % ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) < 4:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    write(argv[1], argv[2], argv[3:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
