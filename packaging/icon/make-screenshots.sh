#!/bin/sh
# Regenerate the web-manifest screenshots under web/screens/ from the
# website's full-size captures.
#
# These are what Chromium's richer install dialog shows beside the name:
# without a "wide" one it falls back to a bare one-line prompt, which is the
# difference between "install this app" reading as an app and reading as a
# browser asking to make a shortcut. They are not icons, so they do not come
# from an SVG master - they are the same captures website/assets already
# ships, downscaled, which is deliberate: the picture in the install dialog
# and the picture on the download page should be the same picture.
#
# JPEG rather than PNG, and downscaled rather than full size, because these
# are embedded in the binary with include_bytes! like the icons. The two
# sources are 2880x1800 and 828x1792 PNGs and total 565 KB; at these sizes
# they total 220 KB, and the dialog renders them a few hundred pixels wide.
#
# Chromium's constraints, all of which the sizes below satisfy: at least
# 320 px and at most 3840 px on each side, an aspect ratio between 1:2.3 and
# 2.3:1, and one ratio per form_factor (so a second "wide" shot must also be
# 8:5). The `sizes` in web/site.webmanifest must match the file exactly - a
# mismatch is silently ignored rather than reported.
#
# The output is committed. Rerun this and commit it whenever the captures in
# website/assets change, and re-check the `sizes` in the manifest.
set -e
cd "$(dirname "$0")"

SRC=../../website/assets
OUT=../../web/screens
mkdir -p "$OUT"

# 8:5, the shape of the 2880x1800 capture.
sips -Z 1280 -s format jpeg -s formatOptions 82 \
  "$SRC/dash-hero.png" --out "$OUT/dash-wide.jpg" >/dev/null
# 195:422, the shape of the phone capture. Inside 1:2.3 with room to spare.
sips -Z 844 -s format jpeg -s formatOptions 82 \
  "$SRC/mobile-dash.png" --out "$OUT/dash-narrow.jpg" >/dev/null

for f in dash-wide dash-narrow; do
  echo "wrote web/screens/$f.jpg"
done
