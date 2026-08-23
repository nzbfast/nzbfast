#!/bin/zsh
# Guard tests for leak-check.sh --rev and for the pre-push hook built on
# it (.githooks/pre-push).
#
# A PUSH ships blobs from COMMITS. On this shared checkout the working
# tree is routinely neither: nine sessions edit it at once, so it holds
# another lane's half-finished work, and your own pushed commit may be
# hours old. A push-time check that read the worktree would therefore be
# wrong in both directions - it would MISS a leak that is in the commit
# and since edited away, and it would REFUSE you for a leak in somebody
# else's uncommitted file. The second is the one that matters: a hook
# that fires on work you did not do is a hook people turn off.
#
# The hook's other judgement is which commits are yours. Not the whole
# `remote_sha..local_sha` range, which on a push to main includes every
# other lane's commit that arrived through the origin/main merge you did
# five minutes ago; `--not --remotes` subtracts everything already on the
# server, and a merge commit contributes only its conflict resolutions.
#
# Run: packaging/tests/leak-check-rev.sh
set -uo pipefail

PKG=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$PKG/.." && pwd)
SCRIPT=$PKG/leak-check.sh
HOOK=$REPO/.githooks/pre-push
[ -f "$SCRIPT" ] || { echo "cannot find leak-check.sh"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# Assembled at runtime and never written literally: packaging/ ships
# publicly and is scanned by the tool under test, so spelling the marker
# out here would make this file its own leak.
LEAK=$(printf '%s-%s' 'm1' 'london')
CLEAN='a 10-core laptop'

# A throwaway private repo laid out like the real one. leak-check.sh
# resolves ROOT as dirname($0)/.., so it has to sit in packaging/, and it
# reads the pattern file and the manifest from there - both copied from
# the real tree so the path predicates and the pattern loading are
# exercised for real rather than against a stub.
make_repo() {
  local root=$1
  mkdir -p "$root/packaging" "$root/crates/nzbkit/src" "$root/research"
  cp "$SCRIPT" "$root/packaging/leak-check.sh"
  cp "$PKG/private-patterns.txt" "$root/packaging/private-patterns.txt"
  cp "$PKG/PUBLIC_MANIFEST" "$root/packaging/PUBLIC_MANIFEST"
  chmod +x "$root/packaging/leak-check.sh"
  git -C "$root" init -q -b main
  git -C "$root" config user.name t
  git -C "$root" config user.email t@t
  echo "// $CLEAN" > "$root/crates/nzbkit/src/thing.rs"
  git -C "$root" add -A >/dev/null 2>&1
  git -C "$root" commit -qm base --no-verify >/dev/null 2>&1
}

commit() { git -C "$1" add -A >/dev/null 2>&1; git -C "$1" commit -qm "$2" --no-verify >/dev/null 2>&1; }

# Run leak-check in $root with the given args and assert the exit code.
expect() {
  local desc=$1 root=$2 want=$3; shift 3
  local out rc
  out=$(cd "$root" && ./packaging/leak-check.sh "$@" 2>&1)
  rc=$?
  if [ $rc -eq "$want" ]; then
    ok "$desc"
  else
    bad "$desc: wanted exit $want, got $rc -- $(echo "$out" | tr '\n' ' ' | head -c 200)"
  fi
}

new_repo() {
  TMP=$(mktemp -d)
  ROOT="$TMP/repo"
  make_repo "$ROOT"
  SRC="$ROOT/crates/nzbkit/src/thing.rs"
}

echo "leak-check.sh --rev judges the named commit"

# 1. THE POINT OF THE MODE. The leaky bytes are the ones the push would
#    ship. A tidy worktree says nothing about them.
new_repo
echo "// benchmarked on $LEAK" > "$SRC"
commit "$ROOT" leak
echo "// benchmarked on $CLEAN" > "$SRC"          # tidied, NOT committed
expect "leaky commit, tidied worktree: refused" "$ROOT" 1 --rev HEAD crates/nzbkit/src/thing.rs
rm -rf "$TMP"

# 2. The mirror image, and the false alarm that would get the hook
#    switched off: somebody else's uncommitted edit is not your push.
new_repo
echo "// benchmarked on $CLEAN" > "$SRC"
commit "$ROOT" clean
echo "// benchmarked on $LEAK" > "$SRC"           # dirty worktree, uncommitted
expect "clean commit, another lane's leaky worktree: allowed" "$ROOT" 0 --rev HEAD crates/nzbkit/src/thing.rs
rm -rf "$TMP"

# 3. A path that is not in that tree is nothing to scan, exactly as a
#    deleted staged path is - and its NAME must not be judged either.
new_repo
expect "path absent from the named tree: skipped, not an error" "$ROOT" 0 \
  --rev HEAD "crates/nzbkit/src/$LEAK.rs"
rm -rf "$TMP"

# 4. No file list means the whole tree at that revision.
new_repo
echo "// benchmarked on $LEAK" > "$SRC"
commit "$ROOT" leak
echo "// benchmarked on $CLEAN" > "$SRC"
commit "$ROOT" fixed
expect "--rev with no files scans that whole tree (clean tip)" "$ROOT" 0 --rev HEAD
expect "--rev with no files scans that whole tree (leaky parent)" "$ROOT" 1 --rev HEAD~1
rm -rf "$TMP"

# 5. A private path stays private business at any revision.
new_repo
echo "notes about $LEAK" > "$ROOT/research/notes.md"
commit "$ROOT" notes
expect "private path in the commit: allowed" "$ROOT" 0 --rev HEAD research/notes.md
rm -rf "$TMP"

# 6. Usage errors are loud. A mode that silently scanned nothing would
#    read exactly like a clean verdict.
new_repo
expect "--rev with no tree-ish: usage error" "$ROOT" 1 --rev
expect "--rev at a name that is not a tree: usage error" "$ROOT" 1 --rev no-such-ref
rm -rf "$TMP"

# 7. The other three modes are untouched by the dispatch rewrite.
new_repo
echo "// benchmarked on $LEAK" > "$SRC"
expect "explicit path still reads the worktree" "$ROOT" 1 crates/nzbkit/src/thing.rs
expect "--all still reads the worktree" "$ROOT" 1 --all
git -C "$ROOT" add crates/nzbkit/src/thing.rs >/dev/null 2>&1
echo "// benchmarked on $CLEAN" > "$SRC"
expect "--staged still reads the index" "$ROOT" 1 --staged
rm -rf "$TMP"

# ------------------------------------------------------------------ hook
if [ ! -x "$HOOK" ]; then
  echo
  echo "no .githooks/pre-push here (the public export's shape) - hook cases skipped"
  echo
  echo "passed: $PASS  failed: $FAIL"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

echo ".githooks/pre-push refuses a push, not a worktree"

# A bare origin plus a work clone wired to the real hook. `git push` is
# driven for real so the stdin contract is exercised rather than mimed.
new_push_repo() {
  TMP=$(mktemp -d)
  ROOT="$TMP/repo"
  make_repo "$ROOT"
  SRC="$ROOT/crates/nzbkit/src/thing.rs"
  # `-b main` explicitly. Without it the bare repo's HEAD follows the
  # BOX's init.defaultBranch, which on a GitHub ubuntu runner is master
  # while these fixtures are `-b main`: the pushed ref is then main, HEAD
  # dangles at master, and `git clone` prints "remote HEAD refers to
  # nonexistent ref" and checks out NOTHING. Every case below that clones
  # a second lane then wrote its fixture into a directory that did not
  # exist, and three of them passed for the wrong reason on the first CI
  # run this suite ever had (23 Aug 2026). clone_other() asserts the
  # checkout is real so that can never be silent again.
  git init -q --bare -b main "$TMP/origin.git"
  git -C "$ROOT" remote add origin "$TMP/origin.git"
  mkdir -p "$ROOT/.githooks"
  cp "$HOOK" "$ROOT/.githooks/pre-push"
  chmod +x "$ROOT/.githooks/pre-push"
  git -C "$ROOT" config core.hooksPath .githooks
  git -C "$ROOT" push -q --no-verify origin main >/dev/null 2>&1
  git -C "$ROOT" fetch -q origin >/dev/null 2>&1
}

# A second lane's clone of the same origin. Aborts the suite rather than
# returning a half-built fixture: a case whose setup silently did nothing
# still reaches its assertion, and "refused"/"allowed" are both things an
# empty fixture can produce by accident.
clone_other() {
  other=$TMP/other
  git clone -q "$TMP/origin.git" "$other" 2>/dev/null
  git -C "$other" config user.name u
  git -C "$other" config user.email u@u
  if [ ! -f "$other/crates/nzbkit/src/thing.rs" ]; then
    echo "  FAIL - fixture: the second lane's clone checked out nothing"
    FAIL=$((FAIL + 1))
    return 1
  fi
  return 0
}

push_expect() {
  local desc=$1 want=$2; shift 2
  local out rc
  out=$(cd "$ROOT" && git push "$@" 2>&1)
  rc=$?
  if [ $rc -eq "$want" ]; then
    ok "$desc"
  else
    bad "$desc: wanted exit $want, got $rc -- $(echo "$out" | tr '\n' ' ' | head -c 200)"
  fi
}

# 8. A planted leak in your own commit is refused.
new_push_repo
echo "// benchmarked on $LEAK" > "$SRC"
commit "$ROOT" leak
push_expect "leak in a pushed commit: refused" 1 origin main
rm -rf "$TMP"

# 9. The ordinary case still goes through. A gate that refuses
#    everything is a gate people stop installing.
new_push_repo
echo "// benchmarked on $CLEAN" > "$SRC"
commit "$ROOT" clean
push_expect "clean commit: allowed" 0 origin main
rm -rf "$TMP"

# 10. THE FALSE ALARM THAT WOULD SINK IT. Another session's uncommitted
#     edit sits in the shared checkout while you push something clean.
#     Two shapes, because they fail differently: a file your push does
#     not touch at all, and the very file your push DOES touch.
new_push_repo
echo "// $CLEAN and more" > "$SRC"
commit "$ROOT" clean
echo "// benchmarked on $LEAK" > "$ROOT/crates/nzbkit/src/other.rs"   # never committed
push_expect "another session's dirty worktree: allowed" 0 origin main
rm -rf "$TMP"

# 10b. The same file, edited under you between your commit and your push.
#      A hook that read the worktree would refuse a commit that is clean.
new_push_repo
echo "// $CLEAN and more" > "$SRC"
commit "$ROOT" clean
echo "// benchmarked on $LEAK" > "$SRC"          # uncommitted edit, same path
push_expect "a leak in the worktree copy of a file you pushed clean: allowed" 0 origin main
rm -rf "$TMP"

# 10c. The mirror. The leak is in the COMMIT and the worktree has since
#      been tidied - the push still ships the leaky blob. Together with
#      10b this is what pins the hook to --rev: reading the worktree
#      passes 8 and 9 and gets both of these backwards.
new_push_repo
echo "// benchmarked on $LEAK" > "$SRC"
commit "$ROOT" leak
echo "// $CLEAN" > "$SRC"                        # tidied, NOT committed
push_expect "leak in the commit, tidied worktree: refused" 1 origin main
rm -rf "$TMP"

# 11. A leak that arrived through a MERGE of work already on the server.
#     Their push already reddened leak-check CI; refusing yours for it is
#     unfixable by you and buys nothing.
new_push_repo
clone_other && {
echo "// benchmarked on $LEAK" > "$other/crates/nzbkit/src/theirs.rs"
commit "$other" theirs
git -C "$other" push -q --no-verify origin main >/dev/null 2>&1
git -C "$ROOT" fetch -q origin
echo "// $CLEAN, mine" > "$SRC"
commit "$ROOT" mine
git -C "$ROOT" merge -q --no-edit origin/main >/dev/null 2>&1
push_expect "leak merged in from origin: not my push to refuse" 0 origin main
}
rm -rf "$TMP"

# 11b. The same, on a TOPIC branch, which is where the plain range
#      `remote_sha..local_sha` and `--not --remotes` actually part
#      company. Pushing to main they agree, because the remote sha you
#      are pushing over already contains the other lane's commit. Pushing
#      a branch, the remote sha is your own older tip, so the range walks
#      straight into everything the origin/main merge brought with it.
new_push_repo
git -C "$ROOT" checkout -qb topic
echo "// $CLEAN, first" > "$SRC"
commit "$ROOT" first
git -C "$ROOT" push -q --no-verify origin topic >/dev/null 2>&1
clone_other && {
git -C "$other" checkout -q main
echo "// benchmarked on $LEAK" > "$other/crates/nzbkit/src/theirs.rs"
commit "$other" theirs
git -C "$other" push -q --no-verify origin main >/dev/null 2>&1
git -C "$ROOT" fetch -q origin
git -C "$ROOT" merge -q --no-edit origin/main >/dev/null 2>&1
echo "// $CLEAN, second" > "$SRC"
commit "$ROOT" second
push_expect "topic branch carrying an origin/main merge: allowed" 0 origin topic
}
rm -rf "$TMP"

# 12. ...but a conflict resolution in that merge IS yours, so it is
#     scanned. `-c` on the combined diff is what makes the difference.
new_push_repo
clone_other && {
echo "// theirs" > "$other/crates/nzbkit/src/thing.rs"
commit "$other" theirs
git -C "$other" push -q --no-verify origin main >/dev/null 2>&1
git -C "$ROOT" fetch -q origin
echo "// mine" > "$SRC"
commit "$ROOT" mine
git -C "$ROOT" merge --no-edit origin/main >/dev/null 2>&1        # conflicts
echo "// benchmarked on $LEAK" > "$SRC"                            # bad resolution
git -C "$ROOT" add crates/nzbkit/src/thing.rs >/dev/null 2>&1
git -C "$ROOT" commit -qm merge --no-verify >/dev/null 2>&1
push_expect "leak typed into a merge resolution: refused" 1 origin main
}
rm -rf "$TMP"

# 13. A brand new branch has no remote sha at all, so the range is
#     everything not already on the server.
new_push_repo
git -C "$ROOT" checkout -qb feature
echo "// benchmarked on $LEAK" > "$SRC"
commit "$ROOT" leak
push_expect "leak on a brand new branch: refused" 1 origin feature
rm -rf "$TMP"

# 14. Deleting a branch ships no bytes.
new_push_repo
git -C "$ROOT" push -q --no-verify origin main:doomed >/dev/null 2>&1
echo "// benchmarked on $LEAK" > "$SRC"        # a leak in the worktree, uncommitted
push_expect "branch deletion: nothing to scan" 0 origin :doomed
rm -rf "$TMP"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
