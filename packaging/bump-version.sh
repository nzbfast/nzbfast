#!/bin/sh
# bump-version.sh <new-version>
#
# One command to move every version reference in lockstep:
#   crates/nzbfast/Cargo.toml   (source of truth)
#   crates/nzbfast-core/Cargo.toml (the bin's bottom layer, split out 2 Sep 2026)
#   crates/nzbfast-unpack/Cargo.toml (the extraction/repair/filing layer, split out 2 Sep 2026)
#   crates/nzbfast-meta/Cargo.toml (the search/index-scan/metadata layer, split out 2 Sep 2026)
#   crates/nzbfast-engine/Cargo.toml (the get download pipeline, split out 2 Sep 2026)
#   crates/nzbfast-daemon/Cargo.toml (serve's daemon layer, split out 2 Sep 2026)
#   crates/nzbfast-tasks/Cargo.toml (serve's background lanes, split out 2 Sep 2026)
#   crates/nzbfast-api/Cargo.toml (serve's request layer, split out 2 Sep 2026)
#   crates/nzbtray/Cargo.toml   (installer stamps both exes)
#   website/download*.html      (16 locales, version-pinned button URLs)
#   (NOT the homebrew formula - see bump-tap.sh, it needs published shas)
#   Cargo.lock                  (via cargo, if available)
#
# Everything it rewrites, it also STAGES, and it verifies the rewrite
# landed before it does. Cutting v1.1.3 the sixteen website files were
# rewritten here and then left unstaged: the bump commit carried
# Cargo.toml alone, the site was published from a tree that still said
# 1.1.2, and every download button in every locale 404'd for two hours.
# The bump is one change; making it land as one is this script's job, not
# the operator's memory. `--no-stage` opts out.
set -eu

NO_STAGE=0
ARGS=""
for a in "$@"; do
    case "$a" in
        --no-stage) NO_STAGE=1 ;;
        *) ARGS="$a" ;;
    esac
done
set -- ${ARGS:-}

NEW=${1:?usage: bump-version.sh [--no-stage] <new-version>}
case "$NEW" in
    *[!0-9.]*|.*|*.) echo "version must be dotted numerals, e.g. 1.0.3" >&2; exit 1 ;;
esac
ROOT=$(cd "$(dirname "$0")/.." && pwd)

bump_toml() {
    # Only the first `version = "..."` line (the [package] one).
    awk -v new="$NEW" '!done && /^version = "/ { sub(/"[^"]*"/, "\"" new "\""); done=1 } { print }' \
        "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

bump_toml "$ROOT/crates/nzbfast/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-core/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-unpack/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-meta/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-engine/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-daemon/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-tasks/Cargo.toml"
bump_toml "$ROOT/crates/nzbfast-api/Cargo.toml"
bump_toml "$ROOT/crates/nzbtray/Cargo.toml"

# The Homebrew formula is NOT bumped here. It needs the sha256 of each
# published archive, which does not exist until the release is uploaded, and a
# formula carrying a new version with last release's hashes fails every user's
# checksum. packaging/homebrew/bump-tap.sh does the whole job after the
# release is published, and pushes it to the tap.

if command -v cargo >/dev/null 2>&1; then
    (cd "$ROOT" && cargo update -q -p nzbfast -p nzbfast-core -p nzbfast-unpack -p nzbfast-meta -p nzbfast-engine -p nzbfast-daemon -p nzbfast-tasks -p nzbfast-api -p nzbtray 2>/dev/null) || true
fi

# Website download buttons are version-pinned (asset filenames inside
# /releases/latest/download/ URLs). They must move in lockstep with the
# release publish or the live site 404s - all locales, one pass. There is
# no partial failure mode: the whole page breaks at once, in all sixteen
# locales, the instant the new release becomes `latest`.
TOUCHED="crates/nzbfast/Cargo.toml crates/nzbfast-core/Cargo.toml crates/nzbfast-unpack/Cargo.toml crates/nzbfast-meta/Cargo.toml crates/nzbfast-engine/Cargo.toml crates/nzbfast-daemon/Cargo.toml crates/nzbfast-tasks/Cargo.toml crates/nzbfast-api/Cargo.toml crates/nzbtray/Cargo.toml"
[ -f "$ROOT/Cargo.lock" ] && TOUCHED="$TOUCHED Cargo.lock"
pages=0
bad=0
for f in "$ROOT"/website/download*.html; do
    [ -f "$f" ] || continue
    sed -i '' -E "s/nzbfast-[0-9]+(\.[0-9]+)+-/nzbfast-$NEW-/g" "$f" 2>/dev/null \
        || sed -i -E "s/nzbfast-[0-9]+(\.[0-9]+)+-/nzbfast-$NEW-/g" "$f"
    # Assert the POSITIVE, the same rule tools/check-site-version.sh
    # applies: the page must now name $NEW and nothing else. A page whose
    # links were restructured out of this pattern rewrites to nothing and
    # would otherwise pass silently, which is how a locale gets left behind.
    have=$(grep -oE 'nzbfast-[0-9]+(\.[0-9]+)+-' "$f" \
           | sed 's/^nzbfast-//; s/-$//' | sort -u | paste -sd, -)
    case "$have" in
        "$NEW") pages=$((pages + 1)); TOUCHED="$TOUCHED website/${f##*/}" ;;
        "")     echo "✗ ${f##*/}: no version-pinned download links to rewrite" >&2; bad=1 ;;
        *)      echo "✗ ${f##*/}: still names $have after the rewrite" >&2; bad=1 ;;
    esac
done
if [ "$bad" -ne 0 ]; then
    echo "REFUSING: the download pages did not all move to $NEW." >&2
    echo "    Fix them before committing - tools/check-site-version.sh --tree" >&2
    echo "    will refuse this tree, and a release cut from it publishes a page" >&2
    echo "    whose every button 404s." >&2
    exit 1
fi

# Stage everything that moved, by EXPLICIT PATH. Never `git add -A`: other
# sessions share this checkout and it would sweep up their work.
STAGED="not staged (--no-stage)"
if [ "$NO_STAGE" -eq 0 ] && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    # shellcheck disable=SC2086 - the list is ours, built above, no globs.
    (cd "$ROOT" && git add -- $TOUCHED) && STAGED="staged"
fi

echo ""
echo "bumped to $NEW ($STAGED):"
grep -Hn '^version' "$ROOT/crates/nzbfast/Cargo.toml" "$ROOT/crates/nzbfast-core/Cargo.toml" "$ROOT/crates/nzbfast-unpack/Cargo.toml" "$ROOT/crates/nzbfast-meta/Cargo.toml" "$ROOT/crates/nzbfast-engine/Cargo.toml" "$ROOT/crates/nzbfast-daemon/Cargo.toml" "$ROOT/crates/nzbfast-tasks/Cargo.toml" "$ROOT/crates/nzbfast-api/Cargo.toml" "$ROOT/crates/nzbtray/Cargo.toml"
echo "  website/download*.html      $pages locale page(s) -> nzbfast-$NEW-*"
echo ""
echo "These are ONE commit. The website pages are version-pinned download"
echo "URLs: commit Cargo.toml without them and the published page 404s every"
echo "button the moment the release goes live (v1.1.1, v1.1.3)."
echo "  verify: tools/check-site-version.sh --tree"
echo "reminder: run packaging/homebrew/bump-tap.sh --push AFTER the release is published"
