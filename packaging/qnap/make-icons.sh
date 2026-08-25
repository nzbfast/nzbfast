#!/bin/sh
# Regenerate the three App Center icons from the committed master raster.
#
#   packaging/qnap/make-icons.sh            regenerate and record
#   packaging/qnap/make-icons.sh --check    prove the committed bytes
#
# QTS wants three files named after the package: 64 px, 80 px, and a
# greyed-out 64 px used while the app is stopped. It serves them from its
# own web image folder as <name>.gif, and qbuild's add_icons() copies
# either `<name>.gif` or `<name>.png` into that slot - so the extension
# on disk is a QDK input name, not the format QTS requires.
#
# We ship PNG. A GIF's one-bit transparency turns the antialiased edge of
# a downscaled 1024 px icon into a ring of white crumbs against the App
# Center's tile; PNG keeps the alpha channel, every browser sniffs the
# real format regardless of the name it is served under, and qbuild
# supports the .png names outright.
#
# Same tool as packaging/icon/make-icon.sh: sips downscaling the one
# committed master, so every platform's icon comes off the same art.
#
# THE THREE PNGS ARE COMMITTED, and until 24 Aug 2026 nothing whatever
# checked they were still what this script produces - so a master edited
# with these downscales forgotten left the App Center tile showing the
# previous mark, silently. tools/icon-downstream-gate.py and the `--check`
# arm below are the two halves that hold them now; see that gate's header
# for the whole design and for what neither half can see. That gate also
# reads the grey icon's PIXELS, which is the one arm a dimension check
# cannot stand in for - the failure this script's greyscale pass exists to
# prevent is an output that is the right size, the right format and the
# wrong colour. Reproducibility is what makes `--check` meaningful and it
# was measured before either was written: on 24 Aug 2026 all three outputs,
# the hand-greyscaled one included, reproduced byte-identically.
#
# Never hand-patch a file under icons/ - the next run undoes it and says
# nothing.
set -e
cd "$(dirname "$0")/../.."
# The greyscale step imports the icon pipeline's PNG reader; without this
# that import drops a __pycache__ directory into packaging/icon/, which is
# untracked, unwanted, and turns up in the next person's git status.
export PYTHONDONTWRITEBYTECODE=1

# DERIVATIONS - the one table this script, packaging/icon/derivations.py
# and tools/icon-downstream-gate.py all read, and the same format the
# three first-generation generators in packaging/icon/ carry.
# "<source> <output> <pixel size> [<transform>]", repo-relative, one row
# per committed raster.
#
# The FOURTH column is why that format grew one: the stopped-state icon is
# a downscale AND a luma pass, which `scale` does not describe. A row here
# needs a matching copy in make-qpkg.sh, which names all three by hand on
# its way into the package - an icon this table produces that qbuild never
# copies is bytes nothing ships, and the gate refuses either way round.
DERIVATIONS="
packaging/icon/icon-1024.png  packaging/qnap/icons/nzbfast.png       64
packaging/icon/icon-1024.png  packaging/qnap/icons/nzbfast_80.png    80
packaging/icon/icon-1024.png  packaging/qnap/icons/nzbfast_gray.png  64  grey
"

CHECK=0
case "$1" in
    --check) CHECK=1 ;;
    "") ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

command -v sips >/dev/null 2>&1 || {
    echo "✗ sips is not on this box - it is macOS-only." >&2
    echo "    On Linux, run tools/icon-downstream-gate.py instead: it checks the" >&2
    echo "    recorded master digest, every dimension and the grey icon's pixels" >&2
    echo "    without rasterizing anything." >&2
    exit 2
}

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

# Downscale into $WORK first, always. In --check mode that is the whole
# job; otherwise the results are moved into place afterwards, so a run
# that dies half way never leaves a partly-written icons/.
#
# Read the table from a FILE and not down a pipe: a `while` on the right
# of a pipe runs in a subshell, where an `exit 1` on a missing master
# would kill only the loop and leave this script reporting success.
printf '%s\n' "$DERIVATIONS" > "$WORK/table"
n=0
while read -r master out size transform; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    [ -f "$master" ] || { echo "✗ $master is missing" >&2; exit 1; }
    dst="$WORK/$(basename "$out")"
    sips -z "$size" "$size" "$master" --out "$dst" >/dev/null
    case "${transform:-scale}" in
        scale) ;;
        # The stopped-state icon. sips cannot do this: `sips -M` against a
        # grey ColorSync profile writes no output at all for an image that
        # has an alpha channel, and it fails silently - the first cut of
        # this script shipped a "grey" icon byte-identical to the colour
        # one, which would have had App Center drawing a stopped app
        # exactly like a running one. Greyscale it by hand instead,
        # reusing the PNG reader the icon pipeline already has.
        grey)
            python3 - "$dst" <<'GRAY'
import sys
sys.path.insert(0, "packaging/icon")
from rasterize import read_png, write_rgba

path = sys.argv[1]
w, h, ch, px = read_png(path)
out = bytearray()
for i in range(0, len(px), ch):
    # Rec. 601 luma, alpha untouched: the tile keeps its shape and its
    # rounded corners, the artwork loses its colour.
    g = (px[i] * 299 + px[i + 1] * 587 + px[i + 2] * 114) // 1000
    out += bytes((g, g, g, px[i + 3] if ch == 4 else 255))
write_rgba(path, w, h, out)
GRAY
            ;;
        *)
            echo "✗ DERIVATIONS names transform '$transform', which this script" >&2
            echo "    cannot perform. Teach it the transform rather than dropping" >&2
            echo "    the column - the gate switches arms on that token too." >&2
            exit 1
            ;;
    esac
    n=$((n + 1))
done < "$WORK/table"

# A zero here is a refusal: an empty table would otherwise report success
# having produced nothing, which is the rubber stamp the gate's own header
# refuses at length.
[ "$n" -gt 0 ] || { echo "✗ the DERIVATIONS table produced nothing" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
    bad=0
    while read -r master out size transform; do
        [ -n "$master" ] || continue
        case "$master" in \#*) continue ;; esac
        if [ ! -f "$out" ]; then
            echo "✗ $out is not committed" >&2
            bad=1
        elif ! cmp -s "$WORK/$(basename "$out")" "$out"; then
            echo "✗ $out differs from what this script produces now" >&2
            bad=1
        fi
    done < "$WORK/table"
    python3 packaging/icon/derivations.py check packaging/qnap/make-icons.sh || bad=1
    if [ "$bad" -ne 0 ]; then
        echo "" >&2
        echo "REFUSING: the committed icons are not what this generator produces." >&2
        echo "    Rerun this script with no arguments and commit what it wrote." >&2
        echo "    Do NOT hand-patch a file under packaging/qnap/icons/ - the next" >&2
        echo "    run undoes it and says nothing." >&2
        exit 1
    fi
    echo "✓ all $n committed App Center icon(s) and their records match this generator"
    exit 0
fi

while read -r master out size transform; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    mkdir -p "$(dirname "$out")"
    cp "$WORK/$(basename "$out")" "$out"
    echo "wrote $out (${size}x${size}, ${transform:-scale})"
done < "$WORK/table"

python3 packaging/icon/derivations.py record packaging/qnap/make-icons.sh
