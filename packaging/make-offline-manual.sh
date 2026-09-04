#!/usr/bin/env bash
# Write the OFFLINE copy of a manual: the shipped HTML with the shared
# design tokens inlined.
#
# bash, not zsh, and that matters: this is the one script in packaging/
# that CI runs ON WINDOWS. Both the sign-windows installer job and the
# release workflow's Windows ARM64 job stage the manual with it, and a
# windows-latest runner has Git bash and no zsh at all - a `#!/bin/zsh`
# here is `bad interpreter: No such file or directory`, exit 126, which
# is exactly how it failed the first time either job was run. Nothing
# below is zsh-specific; `set -o pipefail` is the only reason it is not
# plain `#!/bin/sh`.
#
#   packaging/make-offline-manual.sh <src.html> <dest.html>
#
# docs/MANUAL.html carries `__NZBFAST_UI_TOKENS__` in its <head>, and the
# daemon substitutes web/ui-tokens.html for it when it serves /manual.
# Every packager copied the RAW file instead - Windows installer, macOS
# DMG, Homebrew, portable zips - so the shipped manual carried the marker
# as visible body text and then styled itself against CSS variables that
# were never declared. Nobody who opened it from an installer saw the
# page the daemon serves.
#
# Substituting at package time keeps ONE source of truth: the marker
# stays in docs/, the tokens stay in web/, and no copy of the palette is
# forked into the manual where it would drift.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <src.html> <dest.html>" >&2
  exit 1
fi

SRC=$1
DEST=$2
REPO=$(cd "$(dirname "$0")/.." && pwd)
TOKENS="$REPO/web/ui-tokens.html"

[ -f "$SRC" ] || { echo "no such manual: $SRC" >&2; exit 1; }
[ -f "$TOKENS" ] || { echo "no such token file: $TOKENS" >&2; exit 1; }

mkdir -p "$(dirname "$DEST")"
# Read the marker's replacement from a file rather than building a sed
# expression out of 13 KB of CSS: the tokens contain &, /, backslashes
# and newlines, all of which sed would interpret.
awk -v tokfile="$TOKENS" '
  index($0, "__NZBFAST_UI_TOKENS__") {
    n = index($0, "__NZBFAST_UI_TOKENS__")
    printf "%s", substr($0, 1, n - 1)
    while ((getline line < tokfile) > 0) print line
    close(tokfile)
    print substr($0, n + length("__NZBFAST_UI_TOKENS__"))
    next
  }
  # The app-nav marker is DROPPED, not filled. An offline manual is
  # opened over file:// from a DMG or an installed program folder, where
  # "/", "/wall" and "/#settings" resolve against the filesystem root and
  # every one of them is broken. The in-app copy gets the nav folded in
  # by crates/nzbfast/build.rs instead; here the line simply goes. It is
  # an HTML comment, so this is belt and braces - it would render as
  # nothing either way - but the guard below refuses ANY surviving
  # __NZBFAST_ marker, and that guard is worth more than the one line it
  # costs to keep it honest.
  index($0, "<!--__NZBFAST_APP_NAV__-->") {
    n = index($0, "<!--__NZBFAST_APP_NAV__-->")
    printf "%s", substr($0, 1, n - 1)
    print substr($0, n + length("<!--__NZBFAST_APP_NAV__-->"))
    next
  }
  { print }
' "$SRC" > "$DEST"

# Fail rather than ship a manual that still names the marker. This is the
# whole point of the script, and a silent no-op here is exactly the bug
# it replaces.
if grep -q "__NZBFAST_" "$DEST"; then
  echo "make-offline-manual: $DEST still carries an unsubstituted marker" >&2
  exit 1
fi
if ! grep -q -- "--bg" "$DEST"; then
  echo "make-offline-manual: $DEST has no design tokens - substitution did nothing" >&2
  exit 1
fi
echo "offline manual: $DEST"
