#!/bin/zsh
# Guard tests for leak-check.sh --staged: it must judge the INDEX, and
# only --staged may do so.
#
# The pre-commit hook decides whether a commit is clean. A commit ships
# the staged blob, so that is the only content whose verdict means
# anything. --staged used to take the file LIST from the index and each
# file's CONTENT from the working tree, which is a green light on a
# commit that carries a leak whenever the two differ - and the hook's own
# remediation loop walks you straight into it: hook refuses, author edits
# the file, author re-runs `git commit` WITHOUT `git add`, hook now reads
# the clean worktree and commits the original leaky blob.
#
# The other two modes must keep reading the working tree. Explicit-path
# is how the CI canary in .github/workflows/leak-check.yml proves the
# scanner can still see: it plants an UNTRACKED file and passes it by
# name, so an index read there is fatal, and the canary would read that
# usage error as "caught as expected" - masking exactly the blind-scanner
# failure it exists to detect. --all scanning the worktree is how you
# check work in progress.
#
# Run: packaging/tests/leak-check-staged.sh
set -uo pipefail

SCRIPT=$(cd "$(dirname "$0")/.." && pwd)/leak-check.sh
PKG=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$SCRIPT" ] || { echo "cannot find leak-check.sh"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# Assembled at runtime and never written literally. This test file lives
# in packaging/, which ships publicly and is therefore scanned by the
# tool it is testing - spelling the marker out here would make this file
# its own leak.
LEAK=$(printf '%s-%s' 'm1' 'london')
CLEAN='a 10-core laptop'

# A throwaway private repo laid out like the real one: leak-check.sh
# resolves ROOT as dirname($0)/.., so it has to sit in packaging/, and it
# reads the pattern file and the manifest from there. Both are copied
# from the real tree so the path predicates and the pattern loading are
# exercised for real rather than against a stub.
# The three helpers are staged and NOT stubbed, for the reason
# leak-check.sh states at each: it refuses outright when one is missing,
# because a scanner that cannot run is not a clean tree. privrefs-scan.sh
# derives both of its lists out of publish-public.sh, so that has to be
# the real one too - a stub would derive an empty removal set and the
# private-reference arm would then refuse every file the export deletes.
# FOUR scratch roots stage this script - the four leak-check-*.sh tests -
# and they are deliberately separate. A helper added to leak-check.sh
# tomorrow has to be staged in ALL FOUR, and the symptom of missing one is
# every case in that file failing with the same REFUSED line. That is how
# this one was found, on main, ten minutes after the helper landed.
make_repo() {
  local root=$1
  mkdir -p "$root/packaging" "$root/crates/nzbkit/src" "$root/research"
  cp "$SCRIPT" "$root/packaging/leak-check.sh"
  cp "$PKG/private-patterns.txt" "$root/packaging/private-patterns.txt"
  cp "$PKG/PUBLIC_MANIFEST" "$root/packaging/PUBLIC_MANIFEST"
  cp "$PKG/privrefs-scan.sh" "$root/packaging/privrefs-scan.sh"
  cp "$PKG/ci-private-strip.sh" "$root/packaging/ci-private-strip.sh"
  cp "$PKG/publish-public.sh" "$root/packaging/publish-public.sh"
  chmod +x "$root/packaging/leak-check.sh" \
           "$root/packaging/privrefs-scan.sh" \
           "$root/packaging/ci-private-strip.sh"
  git -C "$root" init -q -b main
  # An initial commit, so `git diff --cached` has a HEAD to diff against.
  git -C "$root" add -A >/dev/null 2>&1
  git -C "$root" -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1
}

# Run leak-check in $root with the given args and assert the exit code.
expect() {
  local desc=$1 root=$2 want=$3; shift 3
  local out rc
  out=$(cd "$root" && ./packaging/leak-check.sh "$@" 2>&1)
  rc=$?
  if [ $rc -eq "$want" ]; then
    ok "$desc"
  else
    bad "$desc: wanted exit $want, got $rc -- $(echo "$out" | tr '\n' ' ' | head -c 160)"
  fi
}

new_repo() {
  TMP=$(mktemp -d)
  ROOT="$TMP/repo"
  make_repo "$ROOT"
  SRC="$ROOT/crates/nzbkit/src/thing.rs"
}

echo "leak-check.sh --staged judges the staged blob"

# 1. THE BUG. The leaky bytes are the ones being committed; the tidy
#    worktree is not. Passing this commit is the whole defect.
new_repo
echo "// benchmarked on $LEAK" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
echo "// benchmarked on $CLEAN" > "$SRC"        # tidied, NOT re-staged
expect "leaky staged blob, tidied worktree: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 2. The mirror image. The staged blob is clean, so the commit is clean.
#    Refusing here is a false alarm, and the documented response to a
#    false alarm is to widen the pattern file - a real weakening.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
echo "// benchmarked on $LEAK" > "$SRC"         # dirty worktree, not staged
expect "clean staged blob, leaky worktree: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

# 3. Same root cause, second hole: --diff-filter=ACMR still lists a
#    staged new file that has since been deleted from the worktree, and
#    the old worktree existence test skipped it. The blob still commits.
new_repo
echo "// benchmarked on $LEAK" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
rm -f "$SRC"
expect "staged then removed from the worktree: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 4. The ordinary case still passes - a gate that refuses everything gets
#    switched off.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "clean staged blob, clean worktree: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

# 5. A staged file that is NOT exported stays private business.
new_repo
echo "notes about $LEAK" > "$ROOT/research/notes.md"
git -C "$ROOT" add research/notes.md
expect "private path staged leaky: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

echo "the other two modes still read the working tree"

# 6. The CI canary's mode. The planted file is UNTRACKED, so there is no
#    index entry to read: an index read makes this a usage error, and the
#    canary would mistake that for a catch.
new_repo
echo "// benchmarked on $LEAK" > "$SRC"         # never staged
expect "explicit path, untracked leaky file: refused" "$ROOT" 1 crates/nzbkit/src/thing.rs
rm -rf "$TMP"

# 7. --all judges the tree in front of you, including unstaged edits.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
git -C "$ROOT" -c user.name=t -c user.email=t@t commit -qm add >/dev/null 2>&1
echo "// benchmarked on $LEAK" > "$SRC"         # unstaged worktree edit
expect "--all sees an unstaged worktree leak: refused" "$ROOT" 1 --all
rm -rf "$TMP"

# 8. --all on a clean tree.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
git -C "$ROOT" -c user.name=t -c user.email=t@t commit -qm add >/dev/null 2>&1
expect "--all on a clean tree: allowed" "$ROOT" 0 --all
rm -rf "$TMP"

# 9. --all's own population gap: `git ls-files` never lists an untracked
#    file, so a leaky file you have written but not yet `git add`ed is
#    absent from the scan entirely - and the verdict line used to read
#    "N public file(s) clean" regardless, which is exactly what a pass
#    looks like for the file you were checking. --all must still exit 0
#    (it never widens what gets SCANNED - refusing your commit over
#    another lane's untracked scratch file in this shared checkout is
#    the false alarm that gets a gate switched off) but it must NAME the
#    file it left out.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
git -C "$ROOT" -c user.name=t -c user.email=t@t commit -qm add >/dev/null 2>&1
echo "// benchmarked on $LEAK" > "$ROOT/crates/nzbkit/src/untracked.rs"   # never git add'ed
out=$(cd "$ROOT" && ./packaging/leak-check.sh --all 2>&1); rc=$?
if [ $rc -ne 0 ]; then
  bad "--all with an untracked file: expected exit 0, got $rc -- $(echo "$out" | tr '\n' ' ' | head -c 160)"
elif printf '%s' "$out" | grep -q 'crates/nzbkit/src/untracked.rs'; then
  ok "--all names the untracked public file it could not scan"
else
  bad "--all silently dropped the untracked file from its verdict: $(printf '%s' "$out" | tr '\n' ' ' | head -c 200)"
fi
rm -rf "$TMP"

# 10. A private (unexported) untracked file must NOT be reported - the
#     warning is scoped to the same PUBLIC_MANIFEST population as the
#     scan itself, never to every untracked file in the working tree.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
git -C "$ROOT" -c user.name=t -c user.email=t@t commit -qm add >/dev/null 2>&1
mkdir -p "$ROOT/research"
echo "notes about $LEAK" > "$ROOT/research/scratch.md"   # untracked, private path
out=$(cd "$ROOT" && ./packaging/leak-check.sh --all 2>&1); rc=$?
if [ $rc -ne 0 ]; then
  bad "--all with an untracked private file: expected exit 0, got $rc -- $(echo "$out" | tr '\n' ' ' | head -c 160)"
elif printf '%s' "$out" | grep -q 'research/scratch.md'; then
  bad "--all reported an untracked PRIVATE file, widening the population: $(printf '%s' "$out" | tr '\n' ' ' | head -c 200)"
else
  ok "--all stays silent about an untracked private-path file"
fi
rm -rf "$TMP"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
