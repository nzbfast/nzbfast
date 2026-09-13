#!/usr/bin/env python3
"""Draw the parfast app icon master (1024px PNG) from code.

icon-downstream-gate: this script COMMITS NOTHING. It writes one PNG to a
path the caller names, and `apps/parfast/mac/make-app.sh` points that at a
temp directory and folds the result straight into the .app, exactly as
macapp/make-app.sh does with its iconset. There is no raster in the tree that
can fall behind the source, so there is no derivation set to hold.

The mark is the app's own signature visual: a strip of source blocks, mostly
present with one damaged and one found elsewhere, over a thinner recovery
band. Pure Python (zlib plus a 4x supersample) so the icon needs no image
library on a fresh box - the repo's other icon pipelines rasterise an SVG,
and adding a rasteriser dependency to a private app tree is not worth it.

    ./make-icon-master.py out.png [--size 1024]
"""

import argparse
import struct
import sys
import zlib

# The palette is tokens.json's, by hand rather than by import: an icon is
# drawn once and a token edit must not silently redraw the app's identity.
GROUND_TOP = (0x17, 0x19, 0x2A)
GROUND_BOTTOM = (0x2B, 0x30, 0x4C)
PRESENT = (0x34, 0xC7, 0x59)
DAMAGED = (0xFF, 0x3B, 0x30)
MISNAMED = (0xFF, 0x9F, 0x0A)
RECOVERY = (0x7D, 0x7A, 0xFF)
SPARE = (0x3C, 0x3B, 0x6E)

SS = 4  # supersample factor


def rounded_rect(x0, y0, x1, y1, r):
    """A predicate over supersampled pixel centres."""
    def inside(x, y):
        if x < x0 or x > x1 or y < y0 or y > y1:
            return False
        cx = min(max(x, x0 + r), x1 - r)
        cy = min(max(y, y0 + r), y1 - r)
        return (x - cx) ** 2 + (y - cy) ** 2 <= r * r
    return inside


def draw(size):
    n = size * SS
    # Accumulate in floats, then average the supersample block down.
    rows = [[(0.0, 0.0, 0.0, 0.0)] * n for _ in range(n)]

    ground = rounded_rect(0, 0, n - 1, n - 1, n * 0.2237)  # macOS squircle-ish

    # The strip: 7 cells across the middle, a gap between them.
    cells = [PRESENT, PRESENT, PRESENT, DAMAGED, PRESENT, MISNAMED, PRESENT]
    strip_x0, strip_x1 = n * 0.150, n * 0.850
    strip_y0, strip_y1 = n * 0.370, n * 0.560
    gap = n * 0.016
    width = (strip_x1 - strip_x0 - gap * (len(cells) - 1)) / len(cells)
    cell_shapes = []
    for i, colour in enumerate(cells):
        x0 = strip_x0 + i * (width + gap)
        cell_shapes.append((rounded_rect(x0, strip_y0, x0 + width, strip_y1, n * 0.020), colour))

    # The recovery band under it: filled portion plus the spare remainder.
    band_y0, band_y1 = n * 0.630, n * 0.700
    band_split = strip_x0 + (strip_x1 - strip_x0) * 0.62
    band_fill = rounded_rect(strip_x0, band_y0, band_split, band_y1, n * 0.018)
    band_spare = rounded_rect(strip_x0, band_y0, strip_x1, band_y1, n * 0.018)

    for y in range(n):
        row = rows[y]
        t = y / (n - 1)
        base = tuple(
            GROUND_TOP[i] + (GROUND_BOTTOM[i] - GROUND_TOP[i]) * t for i in range(3)
        )
        for x in range(n):
            if not ground(x, y):
                continue
            colour = base
            if band_spare(x, y):
                colour = RECOVERY if band_fill(x, y) else SPARE
            else:
                for shape, cell_colour in cell_shapes:
                    if shape(x, y):
                        colour = cell_colour
                        break
            row[x] = (colour[0], colour[1], colour[2], 255.0)

    # Average each SS x SS block down to one output pixel.
    out = bytearray()
    for y in range(size):
        out.append(0)  # PNG filter type 0
        for x in range(size):
            r = g = b = a = 0.0
            for dy in range(SS):
                src = rows[y * SS + dy]
                for dx in range(SS):
                    p = src[x * SS + dx]
                    r += p[0]; g += p[1]; b += p[2]; a += p[3]
            count = SS * SS
            out += bytes((int(r / count), int(g / count), int(b / count), int(a / count)))
    return bytes(out)


def png(size, raw):
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--size", type=int, default=1024)
    args = ap.parse_args()
    with open(args.out, "wb") as fh:
        fh.write(png(args.size, draw(args.size)))
    print(f"wrote {args.out} ({args.size}px)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
