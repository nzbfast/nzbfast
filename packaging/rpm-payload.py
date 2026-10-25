#!/usr/bin/env python3
"""rpm-payload.py <package.rpm> <dest-dir> - unpack an rpm's files, stdlib only.

The scan gate's third way into an .rpm (packaging/scan-release-assets.sh),
after libarchive (`tar`) and `rpm2cpio`. It exists because of where the
packages are now built. Since 23 Oct 2026 the .rpm files come off GitHub's
ubuntu runner, whose rpmbuild writes the STRIPPED cpio payload: every entry
is `07070X` plus an 8-hex-digit file index and nothing else, the name, size
and mode living in the rpm header instead. libarchive 3.7 and 3.8 both
answer "Unrecognized archive format" to it and the release Mac has no rpm,
so the gate refused the first CI-built pair (v1.9.0) as CANNOT INSPECT,
which was the right answer. Real rpm reads the format fine: 4.14 (openSUSE
Leap 15.6), 4.16 (Rocky 9) and 6.0 (Fedora) all verified, installed and
ran the v1.9.0 x86_64 package, with the same binary sha256 on all three.

It also reads the classic `070701` (newc) payload, so a package from an
older builder unpacks the same way.

It REFUSES rather than guesses: an unknown compressor, an unknown cpio
magic, a file index past the header's file list, a stripped entry whose
size runs past the payload, or no regular file at all is an error exit,
because a gate that unpacks half a package and scans that half reports
clean on bytes it never saw.

Only regular files are written (directories are created on the way, links
and devices are skipped - the scan reads file CONTENTS and names). Every
name is confined under <dest-dir>: an absolute or `..` path is refused.
"""
import gzip
import lzma
import os
import struct
import subprocess
import sys

RPMTAG_DIRINDEXES = 1116
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
RPMTAG_FILESIZES = 1028
RPMTAG_FILEMODES = 1030
RPMTAG_LONGFILESIZES = 5008
RPMTAG_PAYLOADCOMPRESSOR = 1125


def die(msg):
    sys.stderr.write(f"rpm-payload: {msg}\n")
    sys.exit(1)


def header(b, off):
    """Parse one rpm header at `off`: (tags, end). tags[tag] = (type, data, count)."""
    if b[off:off + 3] != b"\x8e\xad\xe8":
        die(f"no header magic at {off}")
    n, size = struct.unpack(">II", b[off + 8:off + 16])
    index = off + 16
    store = index + 16 * n
    tags = {}
    for i in range(n):
        tag, typ, o, count = struct.unpack(">IIII", b[index + 16 * i:index + 16 * i + 16])
        tags[tag] = (typ, store + o, count)
    return tags, store + size


def strings(b, tags, tag):
    if tag not in tags:
        return []
    _, o, count = tags[tag]
    out = []
    for _ in range(count):
        end = b.index(b"\0", o)
        out.append(b[o:end].decode("utf-8", "surrogateescape"))
        o = end + 1
    return out


def ints(b, tags, tag, width):
    if tag not in tags:
        return None
    _, o, count = tags[tag]
    fmt = {2: ">H", 4: ">I", 8: ">Q"}[width]
    return [struct.unpack(fmt, b[o + width * i:o + width * (i + 1)])[0] for i in range(count)]


def decompress(name, data):
    if name in ("gzip", ""):
        return gzip.decompress(data)
    if name in ("xz", "lzma"):
        return lzma.decompress(data)
    if name == "zstd":
        # No zstd in the stdlib; the release Mac has the zstd binary.
        try:
            return subprocess.run(["zstd", "-dc"], input=data, capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as e:
            die(f"zstd payload and no working zstd binary: {e}")
    die(f"unknown payload compressor {name!r}")


def safe_join(dest, name):
    if name.startswith("./"):
        name = name[2:]
    rel = name.lstrip("/")
    path = os.path.normpath(os.path.join(dest, rel))
    if not (path == dest or path.startswith(dest + os.sep)):
        die(f"refusing a name outside the destination: {name!r}")
    return path


def write(dest, name, data):
    path = safe_join(dest, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def main():
    if len(sys.argv) != 3:
        die("usage: rpm-payload.py <package.rpm> <dest-dir>")
    b = open(sys.argv[1], "rb").read()
    dest = os.path.realpath(sys.argv[2])
    if b[:4] != b"\xed\xab\xee\xdb":
        die("not an rpm (no lead magic)")
    _, sig_end = header(b, 96)
    main_at = (sig_end + 7) // 8 * 8
    tags, payload_at = header(b, main_at)

    comp = strings(b, tags, RPMTAG_PAYLOADCOMPRESSOR)
    cpio = decompress(comp[0] if comp else "gzip", b[payload_at:])

    dirs = strings(b, tags, RPMTAG_DIRNAMES)
    bases = strings(b, tags, RPMTAG_BASENAMES)
    dix = ints(b, tags, RPMTAG_DIRINDEXES, 4) or []
    names = [dirs[d] + bn for d, bn in zip(dix, bases)]
    sizes = ints(b, tags, RPMTAG_LONGFILESIZES, 8) or ints(b, tags, RPMTAG_FILESIZES, 4) or []
    modes = ints(b, tags, RPMTAG_FILEMODES, 2) or []

    pos, wrote = 0, 0
    while pos < len(cpio):
        magic = cpio[pos:pos + 6]
        if magic == b"07070X":
            fx = int(cpio[pos + 6:pos + 14], 16)
            pos = (pos + 14 + 3) // 4 * 4
            if fx >= len(names) or fx >= len(sizes):
                die(f"stripped entry names file {fx}, the header lists {len(names)}")
            size = sizes[fx]
            if pos + size > len(cpio):
                die(f"stripped entry {names[fx]!r} runs past the payload")
            if modes and (modes[fx] & 0o170000) == 0o100000:
                write(dest, names[fx], cpio[pos:pos + size])
                wrote += 1
            pos = (pos + size + 3) // 4 * 4
        elif magic == b"070701":
            h = cpio[pos:pos + 110]
            f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            mode, size, namesize = f[1], f[6], f[11]
            name = cpio[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "surrogateescape")
            pos = (pos + 110 + namesize + 3) // 4 * 4
            if name == "TRAILER!!!":
                break
            if (mode & 0o170000) == 0o100000:
                write(dest, name, cpio[pos:pos + size])
                wrote += 1
            pos = (pos + size + 3) // 4 * 4
        else:
            die(f"unknown cpio magic {magic!r} at {pos}")
    if wrote == 0:
        die("no regular file in the payload")
    print(f"rpm-payload: {wrote} file(s)")


if __name__ == "__main__":
    main()
