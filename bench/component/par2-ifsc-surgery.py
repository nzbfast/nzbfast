#!/usr/bin/env python3
"""Rewrite the IFSC packets of a PAR2 index so a verify rig can exercise
BlockCheck::UNPROVEN cells on a REAL on-disk set rather than in-library.

Two shapes, both of which our parser turns into placeholder cells:

  --keep N        truncate every IFSC packet to its first N entries. The
                  parser's fit_ifsc() then pads the grid out to the
                  FileDesc's length with UNPROVEN, which is the
                  "short IFSC" shape (M4-37).
  --zero A:B      zero the entries in [A,B) in place. An all-zero MD5 is
                  RESERVED as the unproven marker, and a WIRE entry
                  spelling it reads as unproven too - which is the only
                  way to get an INTERIOR unproven gap.

Packet layout: magic(8) len(8) pkt_md5(16) setid(16) type(16) body.
pkt_md5 covers bytes 32.. of the packet, so every edit needs it redone.
IFSC body: fileid(16) then 20-byte (md5, crc32le) entries.
"""
import hashlib, struct, sys

MAGIC = b"PAR2\x00PKT"
IFSC = b"PAR 2.0\x00IFSC\x00\x00\x00\x00"

def packets(buf):
    off = 0
    while off + 64 <= len(buf):
        if buf[off:off + 8] != MAGIC:
            off += 1
            continue
        ln = struct.unpack_from("<Q", buf, off + 8)[0]
        if ln < 64 or off + ln > len(buf):
            break
        yield off, ln, buf[off:off + ln]
        off += ln

def reseal(pkt):
    body = pkt[32:]
    return pkt[:16] + hashlib.md5(body).digest() + body

def main():
    src, dst = sys.argv[1], sys.argv[2]
    keep = zero = None
    a = sys.argv[3:]
    while a:
        if a[0] == "--keep":
            keep = int(a[1]); a = a[2:]
        elif a[0] == "--zero":
            lo, hi = a[1].split(":"); zero = (int(lo), int(hi)); a = a[2:]
        else:
            sys.exit("unknown arg " + a[0])
    buf = open(src, "rb").read()
    out = bytearray()
    n_ifsc = 0
    for _, _, pkt in packets(buf):
        if pkt[48:64] != IFSC:
            out += pkt
            continue
        n_ifsc += 1
        head, ents = pkt[:80], bytearray(pkt[80:])
        assert len(ents) % 20 == 0, "IFSC body is not a whole number of entries"
        n = len(ents) // 20
        if zero:
            lo, hi = zero
            for i in range(max(0, lo), min(n, hi)):
                ents[i * 20:(i + 1) * 20] = b"\x00" * 20
        if keep is not None and keep < n:
            ents = ents[:keep * 20]
            n = keep
        new = bytearray(head + ents)
        struct.pack_into("<Q", new, 8, len(new))
        out += reseal(bytes(new))
        print(f"  IFSC: {n} entries out")
    if not n_ifsc:
        sys.exit("no IFSC packet found - wrong file?")
    open(dst, "wb").write(bytes(out))
    print(f"wrote {dst} ({len(out)} bytes, {n_ifsc} IFSC packet(s))")

main()
