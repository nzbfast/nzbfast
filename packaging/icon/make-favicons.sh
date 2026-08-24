#!/bin/sh
# Regenerate the browser icons under web/icons/ from the two SVG masters.
#
# These are what a browser needs to pin a tab, make a desktop shortcut or
# install the dashboard to a home screen. The pages used to declare a single
# emoji in a `data:` SVG, which renders in the tab strip but gives the OS
# nothing to build a shortcut icon from - so Windows fell back to a generated
# letter tile, which is what the "logo too small and hard to see" report was
# actually looking at.
#
# 16 and 32 come from icon-small.svg for the same reason the .ico's small
# entries do; the rest come from icon.svg. 180 is Apple's touch icon, 192 and
# 512 are the web-manifest sizes Chrome and Android install from.
#
# The -maskable pair comes from icon-maskable.svg, which is the same art laid
# out for the adaptive-icon mask rather than for a square - see that file's
# header. A launcher that is handed only "any" art insets the whole tile
# inside its mask and fills the gap with white or grey, which is the same
# "logo too small" report one layer up; a manifest that declares both lets it
# pick per surface.
#
# The PNGs are committed and embedded in the binary with include_bytes!, so
# rerun this and commit the output whenever a master changes.
set -e
cd "$(dirname "$0")"

OUT=../../web/icons
mkdir -p "$OUT"

python3 rasterize.py icon-small.svg 16 "$OUT/favicon-16.png"
python3 rasterize.py icon-small.svg 32 "$OUT/favicon-32.png"
python3 rasterize.py icon.svg 180 "$OUT/apple-touch-icon.png"
python3 rasterize.py icon.svg 192 "$OUT/icon-192.png"
python3 rasterize.py icon.svg 512 "$OUT/icon-512.png"
python3 rasterize.py icon-maskable.svg 192 "$OUT/icon-192-maskable.png"
python3 rasterize.py icon-maskable.svg 512 "$OUT/icon-512-maskable.png"

for f in favicon-16 favicon-32 apple-touch-icon icon-192 icon-512 \
         icon-192-maskable icon-512-maskable; do
  echo "wrote web/icons/$f.png"
done
