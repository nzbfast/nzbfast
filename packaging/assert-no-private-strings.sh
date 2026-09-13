#!/bin/sh
# assert-no-private-strings.sh <binary>...
#
# Refuse a binary that carries anything on packaging/private-patterns.txt.
# Exit 0 clean, exit 1 refused with the offending strings printed.
#
# WHY THIS EXISTS, AND WHY AT THE BUILD RATHER THAN THE RELEASE GATE.
#
# Every macOS DMG this project published between v1.0.10 and v1.4.0 -
# 28 releases - shipped 18 to 30 copies of the build account's home
# directory, inside the Swift wrapper. `swift build` records one
# absolute path per object file in the linked binary's debug map (the
# N_OSO stabs); nothing in the source contains it, the Rust engine
# beside it in the same bundle was clean because cargo's
# --remap-path-prefix covers it, and that flag is cargo's and never
# reached Swift.
#
# packaging/scan-release-assets.sh DID run over those DMGs and reported
# clean every time. Its `.dmg` arm read each file with `strings FILE`,
# and `strings` handed a Mach-O PARSES it and walks the sections it
# believes carry text - the debug map is not among them. The `.zip` and
# `.tar.gz` arms streamed raw bytes and would have caught it. Fixed
# 12 Sep 2026, along with this.
#
# So the release gate is no longer blind, and this exists anyway,
# because a single gate that can be blind once can be blind again: a new
# asset type, a new arm, a refactor. This one runs at the moment the
# bytes are CREATED, in the build that creates them, and fails the build
# rather than the upload. Two independent checks over the same property,
# which is the only arrangement that has ever held in this repo.
#
# THE STREAM FORM IS LOAD-BEARING. `strings -a < file`, never
# `strings -a file`. That single difference is the whole defect above.
# Do not "simplify" it.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PATTERNS_FILE="$HERE/private-patterns.txt"
[ -f "$PATTERNS_FILE" ] || {
    echo "assert-no-private-strings: cannot find $PATTERNS_FILE" >&2
    echo "    A check that cannot find its list must not report clean." >&2
    exit 1
}

# Whole-line comments only, the format the file documents for itself.
PATTERNS=$(grep -v '^[[:space:]]*#' "$PATTERNS_FILE" | grep -v '^[[:space:]]*$' \
           | paste -sd '|' -)
[ -n "$PATTERNS" ] || {
    echo "assert-no-private-strings: pattern list parsed to nothing" >&2
    exit 1
}

rc=0
for f in "$@"; do
    [ -f "$f" ] || { echo "assert-no-private-strings: no such file: $f" >&2; rc=1; continue; }
    # `< "$f"` - see the note above. The CI runner homes are blanked the
    # same way scan-release-assets.sh blanks them, so a build on a
    # GitHub runner does not trip on its own legitimate paths.
    hits=$(strings -a < "$f" 2>/dev/null \
           | sed -E -e 's#/(Users|home)/runner([^A-Za-z0-9._-]|$)#/CI/HOME\2#g' \
           | grep -oE "$PATTERNS" | sort -u | head -5 || true)
    if [ -n "$hits" ]; then
        echo "✗ $f carries private strings:" >&2
        printf '    %s\n' $hits >&2
        rc=1
    fi
done

if [ "$rc" -ne 0 ]; then
    echo "" >&2
    echo "REFUSING. A shipped binary must not name the machine that built" >&2
    echo "it. For a Swift wrapper this is the debug map: strip it BEFORE" >&2
    echo "codesign (strip -S). For a Rust binary it is a missing" >&2
    echo "--remap-path-prefix for that target - note that the flag is" >&2
    echo "rustc's and does not reach a C dependency's own paths, which" >&2
    echo "need the C compiler's equivalent." >&2
fi
exit $rc
