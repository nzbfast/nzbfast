#!/bin/sh
# Regenerate the Flatpak icon from the committed master raster.
#
#   packaging/flatpak/make-icon.sh            regenerate and record
#   packaging/flatpak/make-icon.sh --check    prove the committed bytes
#
# Same tool and same master as packaging/qnap/make-icons.sh and
# packaging/icon/make-icon.sh: sips downscaling icon-1024.png, so every
# platform's icon comes off the one piece of art.
#
# PNG rather than the SVG master, even though Flathub accepts either and
# a scalable icon is the nicer thing to ship. appstreamcli compose - the
# step flatpak-builder runs at the end of every build - refuses this
# SVG outright with "Unrecognized image file format", and it is fatal:
# the whole compose run fails and no metadata is produced at all, so the
# build stops with no bundle. It is the icon LOADER that is missing, not
# anything wrong with the file (rsvg-convert renders it fine, and
# appstreamcli succeeds the moment the .svg is not there). A PNG has no
# loader question and meets the requirement either way - Flathub asks for
# an SVG *or* a PNG of at least 256x256.
#
# THE PNG IS COMMITTED, and until 24 Aug 2026 nothing whatever checked it
# was still what this script produces: an edit to the master with this
# downscale forgotten left the Flathub page showing the previous mark,
# silently, for as long as nobody looked. tools/icon-downstream-gate.py
# and the `--check` arm below are the two halves that hold it now - see
# that gate's header for the whole design and for what neither half can
# see. Reproducibility is what makes `--check` meaningful and it was
# measured before either was written: on 24 Aug 2026 this output
# reproduced its committed file byte-identically.
#
# Never hand-patch io.github.nzbfast.nzbfast.png - the next run of this
# script undoes it and says nothing.
set -e
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1

# DERIVATIONS - the one table this script, packaging/icon/derivations.py
# and tools/icon-downstream-gate.py all read, and the same format the
# three first-generation generators in packaging/icon/ carry.
# "<source> <output> <pixel size> [<transform>]", repo-relative, one row
# per committed raster. The transform defaults to `scale`, a plain
# downscale, which is what this one is.
#
# The size here is also the hicolor directory this icon installs into, in
# io.github.nzbfast.nzbfast.yaml - a mismatch between the two is an icon
# filed under a size it is not, which no build step reports. The gate
# holds them together.
DERIVATIONS="
packaging/icon/icon-1024.png  packaging/flatpak/io.github.nzbfast.nzbfast.png  256
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
    echo "    recorded master digest and every dimension arm without rasterizing." >&2
    exit 2
}

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

# Downscale into $WORK first, always. In --check mode that is the whole
# job; otherwise the result is moved into place afterwards, so a run that
# dies half way never leaves a partly-written icon in the tree.
#
# Read the table from a FILE and not down a pipe: a `while` on the right
# of a pipe runs in a subshell, where an `exit 1` on a missing master
# would kill only the loop and leave this script reporting success.
printf '%s\n' "$DERIVATIONS" > "$WORK/table"
n=0
while read -r master out size rest; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    [ -f "$master" ] || { echo "✗ $master is missing" >&2; exit 1; }
    sips -z "$size" "$size" "$master" --out "$WORK/$(basename "$out")" >/dev/null
    n=$((n + 1))
done < "$WORK/table"

# A zero here is a refusal: an empty table would otherwise report success
# having produced nothing, which is the rubber stamp the gate's own
# header refuses at length.
[ "$n" -gt 0 ] || { echo "✗ the DERIVATIONS table produced nothing" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
    bad=0
    while read -r master out size rest; do
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
    python3 packaging/icon/derivations.py check packaging/flatpak/make-icon.sh || bad=1
    if [ "$bad" -ne 0 ]; then
        echo "" >&2
        echo "REFUSING: the committed icon is not what this generator produces." >&2
        echo "    Rerun this script with no arguments and commit what it wrote." >&2
        echo "    Do NOT hand-patch the .png - the next run undoes it and says" >&2
        echo "    nothing." >&2
        exit 1
    fi
    echo "✓ all $n committed flatpak icon(s) and their records match this generator"
    exit 0
fi

while read -r master out size rest; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    mkdir -p "$(dirname "$out")"
    cp "$WORK/$(basename "$out")" "$out"
    echo "wrote $out (${size}x${size})"
done < "$WORK/table"

python3 packaging/icon/derivations.py record packaging/flatpak/make-icon.sh
