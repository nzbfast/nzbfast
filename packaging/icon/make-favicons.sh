#!/bin/sh
# Regenerate the browser icons under web/icons/ from the two SVG masters.
#
#   packaging/icon/make-favicons.sh            regenerate and record
#   packaging/icon/make-favicons.sh --check    prove the committed bytes
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
# THE PNGS ARE COMMITTED and embedded in the binary with include_bytes!, and
# until 24 Aug 2026 "rerun this whenever a master changes" was a sentence in
# this header and nothing else - a convention living only in a comment, which
# is the shape this repo's gate list keeps growing to replace. Two things
# check it now and they are complementary rather than redundant:
#
#   * tools/icons-derived-gate.py, on EVERY branch push, on Linux. It cannot
#     run qlmanage, so what it holds is the sha256 recorded for each master
#     in ICONS-DERIVED.manifest when this last ran, plus every dimension and
#     declaration arm - which need no image tooling at all and catch the
#     failure no digest can: a file whose pixels stop matching the `sizes`
#     string that declares it is dropped SILENTLY.
#
#   * `--check` below, which rasterizes into a temporary directory and
#     compares the BYTES. Stronger, because it proves the output rather than
#     a recorded claim - and macOS-only, so it is a pre-release step and the
#     thing to run after any master edit, never a CI job.
#
# Reproducibility is what makes `--check` meaningful and it was measured
# before either was written: on 24 Aug 2026 every one of the seven rasters
# below reproduced its committed file byte-identically, twice.
#
# Never hand-patch a file under web/icons/ - the next run of this script
# undoes it and says nothing.
set -e
cd "$(dirname "$0")/../.."

# DERIVATIONS - the one table this script, packaging/icon/derivations.py and
# tools/icons-derived-gate.py all read. "<master> <output> <pixel size>",
# repo-relative, one row per committed raster. Every output is square: these
# go through rasterize.py, which renders the SVG at exactly this size and
# refuses anything else.
#
# A row added here needs a matching entry wherever the icon is declared -
# web/site.webmanifest for an install icon, a <link rel="icon"> in
# web/dashboard.html and web/wall.html for a browser one - and an arm in
# crates/nzbfast-api/src/assets.rs to serve it. The gate refuses the tree
# until it has them.
DERIVATIONS="
packaging/icon/icon-small.svg     web/icons/favicon-16.png            16
packaging/icon/icon-small.svg     web/icons/favicon-32.png            32
packaging/icon/icon.svg           web/icons/apple-touch-icon.png     180
packaging/icon/icon.svg           web/icons/icon-192.png             192
packaging/icon/icon.svg           web/icons/icon-512.png             512
packaging/icon/icon-maskable.svg  web/icons/icon-192-maskable.png    192
packaging/icon/icon-maskable.svg  web/icons/icon-512-maskable.png    512
"

CHECK=0
case "$1" in
    --check) CHECK=1 ;;
    "") ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

command -v qlmanage >/dev/null 2>&1 || {
    echo "✗ qlmanage is not on this box - it is macOS-only, and rasterize.py needs it." >&2
    echo "    On Linux, run tools/icons-derived-gate.py instead: it checks the recorded" >&2
    echo "    master digests and every dimension arm without rasterizing anything." >&2
    exit 2
}

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

# Rasterize into $WORK first, always. In --check mode that is the whole job;
# otherwise the results are moved into place afterwards, so a run that dies
# half way never leaves a partly-written web/icons/.
#
# Read the table from a FILE and not down a pipe: a `while` on the right of a
# pipe runs in a subshell, where an `exit 1` on a missing master would kill
# only the loop and leave this script reporting success.
printf '%s\n' "$DERIVATIONS" > "$WORK/table"
n=0
while read -r master out size; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    [ -f "$master" ] || { echo "✗ $master is missing" >&2; exit 1; }
    python3 packaging/icon/rasterize.py "$master" "$size" "$WORK/$(basename "$out")"
    n=$((n + 1))
done < "$WORK/table"

# A zero here is a refusal: an empty table would otherwise report success
# having produced nothing, which is the rubber stamp the gate's own header
# refuses at length.
[ "$n" -gt 0 ] || { echo "✗ the DERIVATIONS table produced nothing" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
    bad=0
    while read -r master out size; do
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
    python3 packaging/icon/derivations.py check make-favicons.sh || bad=1
    if [ "$bad" -ne 0 ]; then
        echo "" >&2
        echo "REFUSING: the committed icons are not what this generator produces." >&2
        echo "    Rerun this script with no arguments and commit what it wrote." >&2
        echo "    Do NOT hand-patch a file under web/icons/ - the next run undoes it" >&2
        echo "    and says nothing." >&2
        exit 1
    fi
    echo "✓ all $n committed browser icon(s) and their records match this generator"
    exit 0
fi

while read -r master out size; do
    [ -n "$master" ] || continue
    case "$master" in \#*) continue ;; esac
    mkdir -p "$(dirname "$out")"
    cp "$WORK/$(basename "$out")" "$out"
    echo "wrote $out"
done < "$WORK/table"

python3 packaging/icon/derivations.py record make-favicons.sh
