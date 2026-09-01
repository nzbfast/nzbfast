#!/usr/bin/env python3
"""par2patch.py - PAR2 packet surgery for the capability corpus.

Some corpus shapes cannot come out of par2cmdline at all, so the sets
are patched after `par2 create` into the shape MultiPar/parpar emit
natively. This is a Python port of the helpers pinned by the e2e suite
(crates/nzbfast/tests/e2e_norar/mod.rs rename_filedesc/empty_filedesc,
crates/nzbfast/tests/e2e_emptydesc/mod.rs splice_zero_member); the
authoritative behavior documentation lives there. The patch edits or
appends packets and reseals each packet MD5 (offset 16..32 covers
setid+type+body), so every packet still verifies; stored file ids are
left alone because every reader keys by the stored id.

    par2patch.py rename <file.par2> <from-name> <to-name>
    par2patch.py splice-empty <file.par2> <name>

Every command re-walks and re-verifies the whole file after editing and
exits nonzero if any packet fails its own MD5 or the intended state is
not present - there is no separate check step to forget.
"""

import hashlib
import struct
import sys

MAGIC = b"PAR2\0PKT"
T_FILEDESC = b"PAR 2.0\0FileDesc"
T_MAIN = b"PAR 2.0\0Main\0\0\0\0"
T_IFSC = b"PAR 2.0\0IFSC\0\0\0\0"
EMPTY_MD5 = hashlib.md5(b"").digest()


def die(msg):
    print(f"[par2patch] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def packets(data):
    """(start, total_len, type) of every structurally valid packet."""
    out = []
    off = 0
    while off + 64 <= len(data):
        rel = data.find(MAGIC, off)
        if rel < 0 or rel + 64 > len(data):
            break
        length = struct.unpack_from("<Q", data, rel + 8)[0]
        if length < 64 or rel + length > len(data):
            off = rel + 1
            continue
        out.append((rel, length, bytes(data[rel + 48 : rel + 64])))
        off = rel + length
    return out


def reseal(data, start, length):
    data[start + 16 : start + 32] = hashlib.md5(
        bytes(data[start + 32 : start + length])
    ).digest()


def filedesc_name(data, start, length):
    raw = bytes(data[start + 120 : start + length])
    return raw.rstrip(b"\0").decode("utf-8", "replace")


def verify(data, want_name=None, want_empty=None):
    """Every packet's MD5 must hold; optional name-presence assertions."""
    names = set()
    n = 0
    for start, length, ptype in packets(data):
        got = bytes(data[start + 16 : start + 32])
        need = hashlib.md5(bytes(data[start + 32 : start + length])).digest()
        if got != need:
            die(f"packet at {start} fails its own MD5 after the edit")
        n += 1
        if ptype == T_FILEDESC:
            names.add(filedesc_name(data, start, length))
    if n == 0:
        die("no packets at all - not a PAR2 file?")
    if want_name is not None and want_name not in names:
        die(f"expected FileDesc name {want_name!r} missing after the edit")
    if want_empty is not None:
        ok = False
        for start, length, ptype in packets(data):
            if ptype != T_FILEDESC or filedesc_name(data, start, length) != want_empty:
                continue
            flen = struct.unpack_from("<Q", data, start + 112)[0]
            md5w = bytes(data[start + 80 : start + 96])
            if flen == 0 and md5w == EMPTY_MD5:
                ok = True
        if not ok:
            die(f"FileDesc {want_empty!r} is not a zero-length descriptor")


def rename_filedesc(data, src, dst):
    """Rewrite every FileDesc named `src` to carry `dst` (null-padded
    into the same region - `dst` must fit)."""
    hits = 0
    for start, length, ptype in packets(data):
        if ptype != T_FILEDESC or filedesc_name(data, start, length) != src:
            continue
        region = length - 120
        if len(dst.encode()) > region:
            die(f"patched name {dst!r} does not fit the {region}-byte region")
        data[start + 120 : start + length] = b"\0" * region
        data[start + 120 : start + 120 + len(dst.encode())] = dst.encode()
        reseal(data, start, length)
        hits += 1
    if hits == 0:
        die(f"no FileDesc named {src!r} to rename")
    return hits


def splice_empty(data, name):
    """Splice a zero-length member named `name` into the set: every Main
    packet copy gains its file id (at the END of the recovery-set list,
    count bumped), and one FileDesc packet for it is appended. A
    zero-length member adds no slices, so recovery data stays valid."""
    nb = name.encode()
    fid = hashlib.md5(EMPTY_MD5 + struct.pack("<Q", 0) + nb).digest()

    desc = bytearray()
    desc += fid
    desc += EMPTY_MD5  # whole-file md5
    desc += EMPTY_MD5  # md5 of the first min(16k, 0) bytes
    desc += struct.pack("<Q", 0)
    desc += nb + b"\0" * (-len(nb) % 4)

    def repack(set_id, ptype, body):
        p = bytearray()
        p += MAGIC
        p += struct.pack("<Q", 64 + len(body))
        p += b"\0" * 16
        p += set_id
        p += ptype
        p += body
        p[16:32] = hashlib.md5(bytes(p[32:])).digest()
        return p

    out = bytearray()
    set_id = None
    mains = 0
    for start, length, ptype in packets(data):
        pkt = data[start : start + length]
        sid = bytes(pkt[32:48])
        if set_id is None:
            set_id = sid
        if ptype == T_MAIN:
            body = bytearray(pkt[64:])
            n = struct.unpack_from("<I", body, 8)[0]
            struct.pack_into("<I", body, 8, n + 1)
            at = 12 + 16 * n
            body[at:at] = fid
            out += repack(sid, T_MAIN, bytes(body))
            mains += 1
        else:
            out += pkt
    if set_id is None:
        die("no packets in input")
    if mains == 0:
        # Volume files carry no Main copy in some layouts; appending the
        # descriptor alone is still valid, but the index file must have
        # patched at least one Main or no reader learns the member exists.
        pass
    out += repack(set_id, T_FILEDESC, bytes(desc))
    data[:] = out
    return mains


def main():
    args = sys.argv[1:]
    if len(args) == 4 and args[0] == "rename":
        _, path, src, dst = args
        data = bytearray(open(path, "rb").read())
        hits = rename_filedesc(data, src, dst)
        verify(data, want_name=dst)
        open(path, "wb").write(data)
        print(f"[par2patch] {path}: renamed {hits} FileDesc packet(s)")
    elif len(args) == 3 and args[0] == "splice-empty":
        _, path, name = args
        data = bytearray(open(path, "rb").read())
        mains = splice_empty(data, name)
        verify(data, want_empty=name)
        open(path, "wb").write(data)
        print(f"[par2patch] {path}: spliced 0-byte {name!r} ({mains} Main copy(ies) patched)")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
