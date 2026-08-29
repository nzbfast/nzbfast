#!/usr/bin/env bash
#
# sync-from-fork.sh — re-vendor the rars perf-fork crate into vendor/rars/.
#
# The fork (github.com/bitplane/rars, perf branch) keeps the crate under
# crates/rars/; the vendored copy here is that crate's root. This script
# mirrors exactly the pieces nzbfast builds and tests against, so a fresh
# `cargo test -p rars --lib` is green on any clean checkout:
#
#   <fork>/crates/rars/src/            -> vendor/rars/src/            (mirror)
#   <fork>/crates/rars/tests/fixtures/ -> vendor/rars/tests/fixtures/ (mirror)
#   <fork>/COPYING                     -> vendor/rars/COPYING
#
# WHY tests/fixtures/** IS NOT OPTIONAL
# ------------------------------------
# The rars unit tests live INLINE in src/lib.rs and read their inputs via
#   env!("CARGO_MANIFEST_DIR")/tests/fixtures/rar15_40/...
# so `cargo test -p rars --lib` fails with NotFound on a clean checkout the
# moment a referenced fixture is missing. Hand-picking "just the fixtures the
# current tests use" is exactly what regressed before (only two were carried
# by hand; four tests broke). This script copies the WHOLE fixtures tree so
# the next inline test that references another fixture can't regress. Do not
# "optimise" it down to a subset.
#
# NOT synced (intentionally):
#   - Cargo.toml : hand-maintained here. The vendored manifest de-workspaces
#     the deps, pins version "0.4.6+nzbfast", adds the forbid-unsafe lints, and
#     drops dev-dependencies/benches. Reconcile it BY HAND after a sync only if
#     the fork's [dependencies] set changed — see VENDORING.md.
#   - tests/*.rs : the fork's integration tests are not vendored (only the
#     inline --lib tests run here), so only their fixtures are needed.
#   - benches/, fuzz/, python/, scripts/, target/, ... : fork-only tooling.
#
# Usage:
#   RARS_FORK=/path/to/rars/checkout ./vendor/rars/sync-from-fork.sh
#   # RARS_FORK defaults to $HOME/Claude/rars
#

# ------------------------------------------------------------------
# OUTBOUND-DRIFT GUARD (added 1 Aug 2026). The vendored copy has taken
# local commits directly and can be AHEAD of the fork; a blind rsync
# --delete would destroy them. Refuse to run while local commits exist
# past the rev recorded in VENDOR-REV, unless --force.
# ------------------------------------------------------------------
HERE="$(cd "$(dirname "$0")" && pwd)"
LAST_SYNC_REV="$(sed -n 's/^last-synced-rev: //p' "$HERE/VENDOR-REV" 2>/dev/null)"
if [ "$1" != "--force" ]; then
  DRIFT="$(cd "$HERE" && git log --oneline --since="2026-08-23T05:13:00-04:00" -- src tests/fixtures COPYING | wc -l | tr -d ' ')"
  if [ "${DRIFT:-0}" -gt 0 ]; then
    echo "REFUSING to sync: vendor/rars has $DRIFT local commits since the last"
    echo "recorded sync ($LAST_SYNC_REV, see VENDOR-REV). Push them to the fork"
    echo "first, update VENDOR-REV, or re-run with --force to discard them."
    exit 1
  fi
fi

set -euo pipefail

fork="${RARS_FORK:-$HOME/Claude/rars}"
crate="$fork/crates/rars"
# The directory this script lives in is the vendored crate root.
dest="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$crate/src" ]; then
  echo "error: '$crate/src' not found." >&2
  echo "       Point RARS_FORK at your rars fork checkout, e.g.:" >&2
  echo "       RARS_FORK=~/src/rars $0" >&2
  exit 1
fi
# Guard the exact regression this script exists to prevent: never vendor a
# crate whose fixtures went missing upstream.
if [ ! -d "$crate/tests/fixtures" ] || [ -z "$(find "$crate/tests/fixtures" -type f -print -quit)" ]; then
  echo "error: '$crate/tests/fixtures' is missing or empty — refusing to vendor" >&2
  echo "       a crate with no test fixtures (the inline --lib tests need them)." >&2
  exit 1
fi

rev="(unknown)"
if git -C "$fork" rev-parse --short HEAD >/dev/null 2>&1; then
  rev="$(git -C "$fork" rev-parse --short HEAD)"
fi
echo "Vendoring rars"
echo "  from : $crate"
echo "  rev  : $rev"
echo "  into : $dest"

# src/ and tests/fixtures/ are exact mirrors (--delete drops files removed
# upstream). tests/*.rs is deliberately excluded from the fixtures sync scope
# because we sync tests/fixtures/ specifically, not tests/.
rsync -a --delete "$crate/src/" "$dest/src/"
mkdir -p "$dest/tests/fixtures"
rsync -a --delete "$crate/tests/fixtures/" "$dest/tests/fixtures/"

# COPYING IS OURS NOW AND IS NOT SYNCED. Until 26 Aug 2026 this script
# copied the fork's repo-root COPYING over ours on every sync, which is
# correct only while our COPYING is upstream's. It no longer is: this
# fork is stated MIT OR Apache-2.0 (see vendor/rars/COPYING for why, and
# LICENSE-MIT / LICENSE-APACHE beside it), so copying upstream's WTFPL
# file back over it would silently revert a deliberate licence decision
# and put the tree back to asserting two licences at once.
#
# Upstream's own COPYING is still worth WATCHING rather than ignoring -
# if bitplane ever resolves his repo's own contradiction, we want to know.
# So report a change instead of applying one.
if   [ -f "$crate/COPYING" ]; then up="$crate/COPYING"
elif [ -f "$fork/COPYING"  ]; then up="$fork/COPYING"
else up=""
fi
if [ -n "$up" ] && ! cmp -s "$up" "$dest/.upstream-COPYING.seen" 2>/dev/null; then
  cp "$up" "$dest/.upstream-COPYING.seen"
  echo "note: upstream COPYING changed - read it and decide whether vendor/rars/COPYING" >&2
  echo "      should follow; it is NOT copied automatically (see the block above)." >&2
fi

n_src=$(find "$dest/src" -type f | wc -l | tr -d ' ')
n_fix=$(find "$dest/tests/fixtures" -type f | wc -l | tr -d ' ')
echo "Synced: $n_src source file(s), $n_fix fixture file(s), COPYING."
echo
echo "NEXT STEPS"
echo "  1. Reconcile vendor/rars/Cargo.toml by hand IF the fork's [dependencies]"
echo "     changed. This script never touches it — see vendor/rars/VENDORING.md."
echo "  2. cargo test -p rars --lib     # must stay green"
echo "  3. git add -A vendor/rars"
echo "     git commit -m 'vendor/rars: sync to fork rev $rev'"
