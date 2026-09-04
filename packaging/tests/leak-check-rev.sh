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
SPLITTER=$REPO/tools/site-leak-scan.py
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
  mkdir -p "$root/packaging" "$root/crates/nzbkit/src" "$root/research" "$root/tools"
  cp "$SCRIPT" "$root/packaging/leak-check.sh"
  cp "$PKG/private-patterns.txt" "$root/packaging/private-patterns.txt"
  cp "$PKG/PUBLIC_MANIFEST" "$root/packaging/PUBLIC_MANIFEST"
  cp "$PKG/privrefs-scan.sh" "$root/packaging/privrefs-scan.sh"
  cp "$PKG/ci-private-strip.sh" "$root/packaging/ci-private-strip.sh"
  cp "$PKG/publish-public.sh" "$root/packaging/publish-public.sh"
  # The region decomposer. leak-check resolves it as ROOT/tools, so a
  # fixture without it exercises the no-decomposer FALLBACK rather than
  # the split - which is a case below, deliberately, and must not be the
  # accidental state of every other one.
  [ -f "$SPLITTER" ] && cp "$SPLITTER" "$root/tools/site-leak-scan.py"
  chmod +x "$root/packaging/leak-check.sh" \
           "$root/packaging/privrefs-scan.sh" \
           "$root/packaging/ci-private-strip.sh"
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

# ------------------------------------------------- raw bytes vs content
# 26 Aug 2026. leak-check used to build ONE alternation out of
# private-patterns.txt and grep it over the raw bytes of every manifest
# file, binary included. Three of those patterns are three characters
# long - the block the pattern file marks `decompressed-only` - so they
# hit BY CHANCE inside compressed bytes, and this scan runs in
# pre-commit, in pre-push and on every push to every branch. The
# identical defect in tools/publish-site.sh refused the v1.2.4 site
# publish over three characters of zlib entropy inside a clean
# screenshot, with the release already live.
#
# The fix is the REGION split, not "stop scanning binaries", and these
# cases pin BOTH directions of that - a planted name in a container's
# METADATA must still be refused, and the same name in its raw
# compressed bytes must not be. Get either half wrong and the change is
# worthless in one direction or dangerous in the other.
echo "raw container bytes get the strong set; content gets the full one"

# The markers are assembled at runtime for the same reason $LEAK is:
# packaging/ ships publicly and is scanned by the tool under test.
BARE=$(printf '%s' 'J''ez')

# A minimal PNG built to order. `where` decides which region the marker
# lands in, and `pixels` is the one that matters: DEFLATE level 0 STORES
# the bytes literally, so the marker is deterministically present in the
# raw container bytes without hunting for a real entropy collision -
# nothing here can go flaky on a future zlib.
make_png() {   # $1 = destination  $2 = text|ztxt|pixels|none  $3 = marker
  python3 - "$1" "$2" "$3" <<'PYEOF'
import struct, sys, zlib
dest, where, marker = sys.argv[1], sys.argv[2], sys.argv[3]
m = marker.encode()
out = bytearray(b"\x89PNG\r\n\x1a\n")
def chunk(t, p):
    out.extend(struct.pack(">I", len(p)))
    out.extend(t + p)
    out.extend(struct.pack(">I", zlib.crc32(t + p) & 0xFFFFFFFF))
raw = b"\x00" + bytes(range(256))
if where == "pixels":
    raw = b"\x00" + b"padding " + m + b" padding"
chunk(b"IHDR", struct.pack(">IIBBBBB", len(raw) - 1, 1, 8, 0, 0, 0, 0))
if where == "text":
    chunk(b"tEXt", b"Author\x00" + m)
elif where == "ztxt":
    chunk(b"zTXt", b"Author\x00\x00" + zlib.compress(m))
# Level 0 for the pixel case so the marker is stored verbatim; the CRC
# is computed over whatever we write, so the file stays a valid PNG.
comp = zlib.compress(raw, 0 if where == "pixels" else 6)
if where == "pixels" and m not in comp:
    raise SystemExit("fixture is broken: level 0 did not store the marker")
chunk(b"IDAT", comp)
chunk(b"IEND", b"")
open(dest, "wb").write(bytes(out))
PYEOF
}

# Something no decomposer here can take apart, which is what 531 of the
# manifest's binary files actually are: archive fixtures and libFuzzer
# crash seeds. The marker sits in the raw bytes with nothing around it
# that could be called text.
make_blob() {   # $1 = destination  $2 = marker
  python3 - "$1" "$2" <<'PYEOF'
import sys
dest, marker = sys.argv[1], sys.argv[2]
body = bytes(range(256)) * 4
i = 64
open(dest, "wb").write(b"Rar!\x1a\x07\x00" + body[:i] + marker.encode() + body[i:])
PYEOF
}

# 15. A bare name in a PNG's UNCOMPRESSED text chunk. The old scan caught
#     this by accident (tEXt is plain bytes); it has to keep catching it
#     on purpose.
new_repo
make_png "$ROOT/web/logo.png" text "$BARE" 2>/dev/null || mkdir -p "$ROOT/web" && make_png "$ROOT/web/logo.png" text "$BARE"
expect "bare name in a PNG tEXt chunk: refused" "$ROOT" 1 web/logo.png
rm -rf "$TMP"

# 16. The same name in a COMPRESSED text chunk. No grep over raw bytes
#     can reach this - it is deflated - so this is coverage the scan did
#     not have before, not coverage it is keeping.
new_repo
mkdir -p "$ROOT/web"
make_png "$ROOT/web/logo.png" ztxt "$BARE"
if grep -aqE "$BARE" "$ROOT/web/logo.png" 2>/dev/null; then
  bad "fixture: the zTXt marker is visible in the raw bytes, so this case proves nothing"
else
  ok "fixture: the zTXt marker really is invisible to a raw grep"
fi
expect "bare name in a PNG zTXt chunk: refused" "$ROOT" 1 web/logo.png
rm -rf "$TMP"

# 17. THE DEFECT. The same three characters in the raw pixel stream, with
#     nothing text-bearing anywhere in the file. Before the split this
#     refused; a chance collision in a real fixture is exactly this
#     shape, and it refuses an ordinary commit.
new_repo
mkdir -p "$ROOT/web"
make_png "$ROOT/web/logo.png" pixels "$BARE"
if grep -aqE "$BARE" "$ROOT/web/logo.png" 2>/dev/null; then
  ok "fixture: the marker really is in the PNG's raw bytes"
else
  bad "fixture: the marker is not in the raw bytes, so this case proves nothing"
fi
expect "bare name only in a PNG's raw pixel bytes: allowed" "$ROOT" 0 web/logo.png
rm -rf "$TMP"

# 18. ...and the split must not have been bought by simply not looking. A
#     STRONG marker in that same pixel stream is still refused, because
#     the strong set runs over raw container bytes.
new_repo
mkdir -p "$ROOT/web"
make_png "$ROOT/web/logo.png" pixels "$LEAK"
expect "a strong marker in the same raw pixel bytes: refused" "$ROOT" 1 web/logo.png
rm -rf "$TMP"

# 19. A format nothing can decompose - the fuzz-seed and archive-fixture
#     case, which is 531 of the manifest's binary files. Strong set only
#     over its raw bytes.
new_repo
make_blob "$ROOT/crates/nzbkit/seed.bin" "$BARE"
expect "bare name in a raw archive-shaped blob: allowed" "$ROOT" 0 crates/nzbkit/seed.bin
rm -rf "$TMP"

new_repo
make_blob "$ROOT/crates/nzbkit/seed.bin" "$LEAK"
expect "strong marker in a raw archive-shaped blob: refused" "$ROOT" 1 crates/nzbkit/seed.bin
rm -rf "$TMP"

# 20. TEXT IS UNTOUCHED. The bare name is the one thing this change
#     narrows, so a plain source file has to keep refusing it - that is
#     the whole population the pattern exists for.
new_repo
printf '// written by %s\n' "$BARE" > "$SRC"
expect "bare name in a source file: still refused" "$ROOT" 1 crates/nzbkit/src/thing.rs
rm -rf "$TMP"

# 21. VERIFIED TO BITE. Take the decomposer away and case 17 goes back to
#     refusing - which pins two things at once: the split is really what
#     changed that verdict, and the fallback fails in the SAFE direction
#     (it can over-report, never under-report) rather than silently
#     scanning nothing.
new_repo
mkdir -p "$ROOT/web"
make_png "$ROOT/web/logo.png" pixels "$BARE"
rm -f "$ROOT/tools/site-leak-scan.py"
expect "no decomposer: falls back to the full set over raw bytes" "$ROOT" 1 web/logo.png
rm -rf "$TMP"

# 22. The split itself is checked on every run, not assumed. Collapse the
#     sentinels in the pattern file and the strong set becomes the full
#     set - which is the state the whole change exists to avoid, so the
#     script must refuse to render a verdict at all rather than report a
#     tree clean under a scanner it can no longer describe.
new_repo
grep -v 'decompressed-only' "$PKG/private-patterns.txt" > "$ROOT/packaging/private-patterns.txt"
printf '// nothing to see\n' > "$SRC"
expect "sentinels removed, so the two sets are identical: refuses to judge" "$ROOT" 1 --all
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

# ---------------------------------------------------- claims ledger half
#
# The hook runs TWO checks over one commit set, and they are deliberately
# independent. `research/CLAIMS.jsonl` is the cross-machine LOCK and is
# append-only by convention only; measured 31 Aug 2026 over all 13,285
# commits reachable from origin/main, SIX commits destroyed a record and
# FOUR records are still absent. `tools/claims-drop-gate.py` refuses that
# at the last moment it is still local.
#
# Case 17 is the one that earns its keep. The hook used to open with three
# lines that `exit 0`'d the WHOLE hook when leak-check.sh was missing, and
# the claims check added below them silently inherited that precondition:
# a real `git push` of a real record drop was ACCEPTED at exit 0. Found by
# driving a push in a fixture without the leak checker, not by reading the
# hook. Each check now tests its own availability; these cases pin that
# neither can be switched off by the other going missing.
GATE=$REPO/tools/claims-drop-gate.py
if [ ! -x "$GATE" ]; then
  echo "no tools/claims-drop-gate.py here - claims hook cases skipped"
else
echo
echo ".githooks/pre-push refuses a commit that destroys a ledger record"

LEDGER=research/CLAIMS.jsonl
seed_ledger() {
  cp "$GATE" "$ROOT/tools/claims-drop-gate.py"
  chmod +x "$ROOT/tools/claims-drop-gate.py"
  printf '%s\n%s\n' \
    '{"ev":"CLAIM","id":"mine","ts":"2026-01-01T00:00:00Z"}' \
    '{"ev":"CLAIM","id":"theirs","ts":"2026-01-02T00:00:00Z"}' \
    > "$ROOT/$LEDGER"
  git -C "$ROOT" add -A >/dev/null 2>&1
  git -C "$ROOT" commit -qm "seed ledger" --no-verify >/dev/null 2>&1
  git -C "$ROOT" push -q --no-verify origin main >/dev/null 2>&1
  git -C "$ROOT" fetch -q origin >/dev/null 2>&1
}
drop_theirs() {
  printf '%s\n' '{"ev":"CLAIM","id":"mine","ts":"2026-01-01T00:00:00Z"}' \
    > "$ROOT/$LEDGER"
}

# 15. The defect itself: a resolution that keeps only your own append.
new_push_repo
seed_ledger
drop_theirs
commit "$ROOT" "claims: close mine"
push_expect "a commit destroying another lane's record: refused" 1 origin main
rm -rf "$TMP"

# 16. The waiver, which must be a REASON and not just the token.
new_push_repo
seed_ledger
drop_theirs
git -C "$ROOT" add -A >/dev/null 2>&1
git -C "$ROOT" commit -q --no-verify -m "claims: close mine

claims-drop-gate: theirs was a malformed hand-typed record" >/dev/null 2>&1
push_expect "a destroyed record with a waiver trailer: allowed" 0 origin main
rm -rf "$TMP"

# 17. THE COUPLING. No leak checker in the fixture at all: the claims
#     check must still fire. This case was RED before the hook was
#     restructured on 31 Aug 2026.
new_push_repo
seed_ledger
rm -f "$ROOT/packaging/leak-check.sh"
drop_theirs
commit "$ROOT" "claims: close mine"
push_expect "record drop refused with no leak checker present" 1 origin main
rm -rf "$TMP"

# 18. And the mirror, so the decoupling is pinned in both directions: no
#     claims gate present, and a leak must still be refused.
new_push_repo
seed_ledger
rm -f "$ROOT/tools/claims-drop-gate.py"
echo "// benchmarked on $LEAK" > "$SRC"
commit "$ROOT" leak
push_expect "leak refused with no claims gate present" 1 origin main
rm -rf "$TMP"

# 19. An ordinary append is not a drop - the control, without which every
#     case above is satisfied by a hook that refuses everything.
new_push_repo
seed_ledger
printf '%s\n%s\n%s\n' \
  '{"ev":"CLAIM","id":"mine","ts":"2026-01-01T00:00:00Z"}' \
  '{"ev":"CLAIM","id":"theirs","ts":"2026-01-02T00:00:00Z"}' \
  '{"ev":"DONE","id":"mine","ts":"2026-01-03T00:00:00Z"}' > "$ROOT/$LEDGER"
commit "$ROOT" "claims: done mine"
push_expect "an ordinary ledger append: allowed" 0 origin main
rm -rf "$TMP"
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
