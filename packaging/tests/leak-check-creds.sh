#!/bin/zsh
# Guard tests for leak-check.sh's credential-shape scan (TODO 63e) and
# the public-file announcement (TODO 63d).
#
# The pattern list only knows values that already leaked; the cred scan
# judges SHAPE. These tests pin the contract: a dense literal next to a
# credential key in a PUBLIC file refuses the commit; placeholders,
# locale label text, and the inline waiver pass; private files stay
# private business. Every marker is assembled at runtime because this
# file itself ships publicly and is scanned by the tool it tests.
#
# Run: packaging/tests/leak-check-creds.sh
set -uo pipefail

SCRIPT=$(cd "$(dirname "$0")/.." && pwd)/leak-check.sh
PKG=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$SCRIPT" ] || { echo "cannot find leak-check.sh"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# Credential-shaped values, assembled so no fragment is itself one.
DENSE=$(printf '%s%s' 'Zk8qTr3v' 'Np2mX9wL')       # 3 classes, 16 chars
DIGITY=$(printf '%s%s' 'une29' '21688')             # lower+digit, the leaked shape
WAIVER=$(printf '%s-%s-%s' 'leakcheck' 'allow' 'synthetic')

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
  git -C "$root" add -A >/dev/null 2>&1
  git -C "$root" -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1
}

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

echo "credential-shape scan (63e)"

# 1. A dense mixed-class literal next to a credential key, staged in a
#    public file: refused. This is the forward-looking case the pattern
#    list can never cover.
new_repo
echo "let api_key = \"$DENSE\";" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "dense literal after api_key: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 2. The lower+digit shape of the credentials that actually leaked.
new_repo
echo "let password = \"$DIGITY\";" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "lower+digit literal after password: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 3. Placeholders and template expansions next to the same keys pass -
#    a gate that refuses documentation examples gets switched off.
new_repo
cat > "$SRC" <<'EOF'
let password = "changeme";
let apikey = "${NZBFAST_KEY}";
let user = "your-username";
let pass = "one-time-passcode";
EOF
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "placeholder values: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

# 4. Locale label text: natural-language (non-ASCII included) values of
#    pass/user keys are UI copy, not credentials.
new_repo
printf '{"srv_pass": "Adgangskode", "srv_user": "Benutzername"}\n' \
  > "$ROOT/crates/nzbkit/src/labels.json"
git -C "$ROOT" add crates/nzbkit/src/labels.json
expect "locale label text: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

# 5. The inline waiver on the SAME line lets a stated-synthetic vector
#    through, on the record in the diff.
new_repo
echo "let api_key = \"$DENSE\"; // $WAIVER: test vector" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "same-line waiver: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

# 6. The waiver is same-line only - one on the line above waives nothing.
new_repo
printf '// %s\nlet api_key = "%s";\n' "$WAIVER" "$DENSE" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "waiver on the line above: still refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 7. Private files keep private business, credential-shaped or not.
new_repo
echo "password = \"$DENSE\"" > "$ROOT/research/notes.md"
git -C "$ROOT" add research/notes.md
expect "private path: allowed" "$ROOT" 0 --staged
rm -rf "$TMP"

# 8. Staged-vs-worktree discipline holds for the cred scan too: the
#    leaky STAGED blob is judged, not the tidied worktree.
new_repo
echo "let token = \"$DENSE\";" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
echo "let token = \"redacted\";" > "$SRC"
expect "leaky staged blob, tidied worktree: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 11. Placeholder SATURATION must not consume the scan. The raw grep
#     used to be capped at 50 lines before any placeholder/shape
#     filtering, so 50 lines of `changeme` hid the real credential
#     underneath them - in a gate that sits immediately before an
#     irreversible public push.
new_repo
{
  i=1
  while [ $i -le 60 ]; do
    echo "let password = \"changeme$i\";"
    i=$((i + 1))
  done
  echo "let api_key = \"$DENSE\";"
} > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "60 placeholders then a real secret: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

# 12. Same saturation, one line: token extraction used to read only the
#     FIRST match on a line, so a placeholder in front of a credential
#     was the only thing judged.
new_repo
echo "let password = \"changeme\"; let api_key = \"$DENSE\";" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
expect "placeholder before a real secret on one line: refused" "$ROOT" 1 --staged
rm -rf "$TMP"

echo "public-file announcement (63d)"

# 9. A clean staged public file gets named out loud, with the repo it
#    ships to - the author must find out where they are standing.
new_repo
echo "// a perfectly clean comment" > "$SRC"
git -C "$ROOT" add crates/nzbkit/src/thing.rs
out=$(cd "$ROOT" && ./packaging/leak-check.sh --staged 2>&1)
if [ $? -eq 0 ] && echo "$out" | grep -q "ship VERBATIM" \
   && echo "$out" | grep -q "crates/nzbkit/src/thing.rs"; then
  ok "clean staged public file is announced by name"
else
  bad "clean staged public file is announced by name -- $(echo "$out" | tr '\n' ' ' | head -c 160)"
fi
rm -rf "$TMP"

# 10. A commit touching only private files stays quiet about shipping.
new_repo
echo "private note" > "$ROOT/research/notes.md"
git -C "$ROOT" add research/notes.md
out=$(cd "$ROOT" && ./packaging/leak-check.sh --staged 2>&1)
if [ $? -eq 0 ] && ! echo "$out" | grep -q "ship VERBATIM"; then
  ok "private-only commit: no announcement"
else
  bad "private-only commit: no announcement -- $(echo "$out" | tr '\n' ' ' | head -c 160)"
fi
rm -rf "$TMP"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
