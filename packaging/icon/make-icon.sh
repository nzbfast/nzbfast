#!/bin/sh
# Regenerate the nzbfast icon artifacts from the two masters. Produces:
#   icon-1024.png    committed source-of-truth raster (large art)
#   NzbFast.icns     (not committed; consumed by macapp/make-app.sh)
# Windows: run make-ico.py for nzbfast.ico, same masters.
#
#   packaging/icon/make-icon.sh [out.icns]   regenerate and record
#   packaging/icon/make-icon.sh --check      prove the committed bytes
#
# Two masters, one per size band - .icns stores an image per size, so this
# is the format working as intended rather than a compromise:
#   icon-small.svg   16 and 32 px entries (bolt alone)
#   icon.svg         64 px and up        (bolt plus slipstream)
# At 16 px the slipstream and the bolt fight over the same handful of pixels.
#
# rasterize.py drives qlmanage (WebKit) and recovers a real alpha channel;
# qlmanage on its own flattens onto opaque white, which is how every icon we
# shipped ended up with a white square behind the rounded tile. sips is only
# used where it downscales an already-transparent PNG. Stock macOS tools
# plus python3 - no third-party deps.
#
# icon-1024.png IS COMMITTED, and it is the master raster four other
# platforms downscale in turn: packaging/flatpak/make-icon.sh,
# packaging/qnap/make-icons.sh, macapp/make-app.sh's own iconset, and
# make-ico.py's entries from 48 px up. Nothing checked it was still what
# icon.svg produces. tools/icons-derived-gate.py holds the recorded digest
# on every branch push; `--check` below proves the bytes, and needs a mac.
set -e
# Resolve the .icns destination BEFORE the cd, so a relative path a caller
# passes still means what that caller meant.
ICNS_ARG=""
CHECK=0
case "$1" in
    --check) CHECK=1 ;;
    "") ;;
    -*) echo "usage: $0 [--check | <out.icns>]" >&2; exit 2 ;;
    /*) ICNS_ARG="$1" ;;
    *) ICNS_ARG="$PWD/$1" ;;
esac
cd "$(dirname "$0")/../.."

# DERIVATIONS - the table this script, packaging/icon/derivations.py and
# tools/icons-derived-gate.py all read. "<master> <output> <pixel size>",
# repo-relative. Only COMMITTED outputs belong here: the .icns below is
# built into a temp directory for macapp/make-app.sh and never lands in the
# tree, so nothing downstream could go stale behind it.
DERIVATIONS="
packaging/icon/icon.svg    packaging/icon/icon-1024.png    1024
"

command -v qlmanage >/dev/null 2>&1 || {
    echo "✗ qlmanage is not on this box - it is macOS-only, and rasterize.py needs it." >&2
    echo "    On Linux, run tools/icons-derived-gate.py instead: it checks the recorded" >&2
    echo "    master digest without rasterizing anything." >&2
    exit 2
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

printf '%s\n' "$DERIVATIONS" > "$TMP/table"
n=0
while read -r master out size; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    [ -f "$master" ] || { echo "✗ $master is missing" >&2; exit 1; }
    python3 packaging/icon/rasterize.py "$master" "$size" "$TMP/$(basename "$out")"
    n=$((n + 1))
done < "$TMP/table"
[ "$n" -gt 0 ] || { echo "✗ the DERIVATIONS table produced nothing" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
    bad=0
    while read -r master out size; do
        [ -n "$master" ] || continue
        case "$master" in \#*) continue ;; esac
        if [ ! -f "$out" ]; then
            echo "✗ $out is not committed" >&2
            bad=1
        elif ! cmp -s "$TMP/$(basename "$out")" "$out"; then
            echo "✗ $out differs from what this script produces now" >&2
            bad=1
        fi
    done < "$TMP/table"
    python3 packaging/icon/derivations.py check make-icon.sh || bad=1
    if [ "$bad" -ne 0 ]; then
        echo "" >&2
        echo "REFUSING: the committed master raster is not what this generator produces." >&2
        echo "    Rerun this script with no arguments and commit what it wrote - and" >&2
        echo "    rerun make-ico.py, packaging/flatpak/make-icon.sh and" >&2
        echo "    packaging/qnap/make-icons.sh, which all downscale it in turn." >&2
        exit 1
    fi
    echo "✓ the committed master raster and its record match this generator"
    exit 0
fi

while read -r master out size; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    cp "$TMP/$(basename "$out")" "$out"
    echo "wrote $out"
done < "$TMP/table"

python3 packaging/icon/derivations.py record make-icon.sh

# Full iconset for iconutil. The two 16 px entries come from the small
# master; everything from icon_32x32@2x (64 px) up comes from the large one,
# downscaled from the 1024 master so the whole band stays pixel-consistent.
# Not committed, so it carries no DERIVATIONS row.
ICONSET="$TMP/NzbFast.iconset"
mkdir -p "$ICONSET"
python3 packaging/icon/rasterize.py packaging/icon/icon-small.svg 16 "$ICONSET/icon_16x16.png"
python3 packaging/icon/rasterize.py packaging/icon/icon-small.svg 32 "$ICONSET/icon_16x16@2x.png"
python3 packaging/icon/rasterize.py packaging/icon/icon-small.svg 32 "$ICONSET/icon_32x32.png"
for entry in 64:icon_32x32@2x 128:icon_128x128 256:icon_128x128@2x \
             256:icon_256x256 512:icon_256x256@2x 512:icon_512x512 \
             1024:icon_512x512@2x; do
  size=${entry%%:*}; name=${entry#*:}
  sips -z "$size" "$size" packaging/icon/icon-1024.png --out "$ICONSET/$name.png" >/dev/null
done
OUT_ICNS=${ICNS_ARG:-$PWD/packaging/icon/NzbFast.icns}
iconutil -c icns "$ICONSET" -o "$OUT_ICNS"
echo "wrote $OUT_ICNS"
