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
# mismatch is silently ignored rather than reported. Every one of those is
# now CHECKED, by tools/screens-derived-gate.py, which reads the DERIVATIONS
# table below as its roster - so a third screenshot added here lands covered
# rather than unseen.
#
# THE OUTPUT IS COMMITTED, and until 24 Aug 2026 that sentence and a request
# to rerun this whenever the captures change was the whole of what kept it
# current: a convention living only in a comment, which is the shape this
# repo's gate list keeps growing to replace. Two things check it now, and
# they are complementary rather than redundant:
#
#   * tools/screens-derived-gate.py, which runs on EVERY branch push on
#     Linux. It cannot run `sips`, so what it holds is the sha256 this
#     script recorded for each SOURCE in website/SCREENS-DERIVED.manifest
#     when it last ran - plus every dimension, ratio and declaration arm,
#     which need no image tooling at all. That is the arm that reddens when
#     a capture is re-shot and its derivative is forgotten.
#
#   * `--check` below, which regenerates into a temporary directory and
#     compares the BYTES. Stronger, because it proves the output rather
#     than a recorded claim - and macOS-only, so it is a pre-release step
#     and the thing to run after any re-shoot, never a CI job.
#
# Reproducibility is what makes `--check` meaningful and it was measured
# before either was written: on 24 Aug 2026 re-running the two `sips` lines
# by hand reproduced both committed files byte-identically.
#
# So: rerun this on a mac whenever the captures in website/assets change,
# commit the .jpg files AND the manifest it rewrites, and re-check the
# `sizes` in web/site.webmanifest. Never hand-patch a file under
# web/screens/ - the next run of this script undoes it and says nothing.
# icons-derived-gate: this is not an icon generator. It downscales the
# website's dashboard captures for the PWA install dialog and touches no SVG
# master; tools/screens-derived-gate.py is the gate that holds it.
set -e
cd "$(dirname "$0")"

SRC=../../website/assets
OUT=../../web/screens
# Written by this script, read by tools/screens-derived-gate.py. Private:
# tools/publish-site.sh copies website/*.html, $EXTRA_ROOT_FILES and
# website/assets/ only, so a build-side file at the website/ root stays
# private, exactly like website/SCREENSHOTS.manifest beside it.
REC=../../website/SCREENS-DERIVED.manifest

# DERIVATIONS - the one table this script and the gate both read.
# "<source under website/assets> <output under web/screens> <long edge>",
# one row per screenshot. The long edge is the `sips -Z` argument: it fits
# the LONGEST side to that many pixels, preserving the aspect ratio, and
# never upscales.
#
#   dash-hero.png is 2880x1800, so 1280 gives 1280x800 - 8:5.
#   mobile-dash.png is 828x1792, so 844 gives 390x844 - 195:422, inside
#   Chromium's 1:2.3 with room to spare.
#
# A row added here needs a matching `screenshots` entry in
# web/site.webmanifest, and the gate refuses the tree until it has one.
DERIVATIONS="
dash-hero.png    dash-wide.jpg    1280
mobile-dash.png  dash-narrow.jpg  844
"

CHECK=0
case "$1" in
    --check) CHECK=1 ;;
    "") ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

command -v sips >/dev/null 2>&1 || {
    echo "✗ sips is not on this box - it is macOS-only, and this script needs it." >&2
    echo "    On Linux, run tools/screens-derived-gate.py instead: it checks the" >&2
    echo "    recorded source digests and every dimension arm without regenerating." >&2
    exit 2
}

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

# Regenerate into $WORK first, always. In --check mode that is the whole
# job; otherwise the results are moved into place afterwards. Doing it this
# way round means a failed run never leaves a half-written web/screens/.
RECORD="$WORK/manifest"
{
    echo "# SCREENS-DERIVED.manifest - GENERATED by packaging/icon/make-screenshots.sh."
    echo "#"
    echo "# One record per file in web/screens/:"
    echo "#"
    echo "#     derived <output> <source> <sha256 of the source when it was generated>"
    echo "#"
    echo "# Held by tools/screens-derived-gate.py, which refuses the tree when a"
    echo "# source has moved since - which is how a re-shot capture whose install-"
    echo "# dialog derivative was forgotten becomes a red line instead of a picture"
    echo "# of an old product. DO NOT HAND-EDIT: rerun the generator on a mac and"
    echo "# commit what it wrote. Editing a digest here without regenerating is the"
    echo "# one edit that gate cannot see, and it defeats it completely."
    echo "#"
    echo "# This file is NOT published - see the REC comment in the generator."
    echo ""
} > "$RECORD"

# Read from a FILE and not down a pipe: a `while` on the right of a pipe
# runs in a subshell, where an `exit 1` on a missing source would kill only
# the loop and leave this script reporting success.
printf '%s\n' "$DERIVATIONS" > "$WORK/table"
while read -r src out edge; do
    [ -n "$src" ] || continue
    case "$src" in \#*) continue ;; esac
    [ -f "$SRC/$src" ] || { echo "✗ $SRC/$src is missing" >&2; exit 1; }
    sips -Z "$edge" -s format jpeg -s formatOptions 82 \
        "$SRC/$src" --out "$WORK/$out" >/dev/null
    digest=$(shasum -a 256 "$SRC/$src" | cut -d' ' -f1)
    printf 'derived  %-16s %-18s %s\n' "$out" "$src" "$digest" >> "$RECORD"
done < "$WORK/table"

# A zero here is a refusal: an empty table would otherwise report success
# having produced nothing, which is the rubber stamp the gate's own header
# refuses at length.
produced=$(grep -c '^derived ' "$RECORD" || true)
[ "$produced" -gt 0 ] || { echo "✗ the DERIVATIONS table produced nothing" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
    bad=0
    for f in $(grep '^derived ' "$RECORD" | awk '{print $2}'); do
        if [ ! -f "$OUT/$f" ]; then
            echo "✗ web/screens/$f is not committed" >&2
            bad=1
        elif ! cmp -s "$WORK/$f" "$OUT/$f"; then
            echo "✗ web/screens/$f differs from what this script produces now" >&2
            bad=1
        fi
    done
    if ! cmp -s "$RECORD" "$REC"; then
        echo "✗ website/SCREENS-DERIVED.manifest differs from what this script writes now" >&2
        bad=1
    fi
    if [ "$bad" -ne 0 ]; then
        echo "" >&2
        echo "REFUSING: the committed output is not what this generator produces." >&2
        echo "    Rerun this script with no arguments and commit what it wrote." >&2
        echo "    Do NOT hand-patch a file under web/screens/ - the next run undoes it" >&2
        echo "    and says nothing." >&2
        exit 1
    fi
    echo "✓ all $produced committed screenshot(s) and the manifest match this generator"
    exit 0
fi

mkdir -p "$OUT"
for f in $(grep '^derived ' "$RECORD" | awk '{print $2}'); do
    cp "$WORK/$f" "$OUT/$f"
    echo "wrote web/screens/$f"
done
cp "$RECORD" "$REC"
echo "wrote website/SCREENS-DERIVED.manifest"
