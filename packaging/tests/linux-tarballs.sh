#!/bin/sh
# The human-download Linux tarballs: owner metadata, and the gate that
# refuses an asset carrying it.
#
# tar writes the BUILDING ACCOUNT's uid, gid, user name and group name
# into every member header unless the builder passes flags telling it
# not to. This project is anonymous in public, so those headers are an
# identity leak in a field no unpacker shows and `tar tzvf` on the
# release Mac does not complain about.
#
# Why a structural check and not the pattern scanner: scan-release-
# assets.sh DOES refuse such a tarball today, but only because the
# literal build account name is in packaging/private-patterns.txt.
# Built anywhere else - a CI runner, a new machine - the same omission
# produces `uname='runner'`, which no pattern knows and which sails
# through. Measured 15 Aug 2026, both halves.
#
# Needs no cross-compiler: the builder prints its flags and stops.
#
# Run: packaging/tests/linux-tarballs.sh
set -u

cd "$(dirname "$0")/../.." || exit 1
PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "1. the builder's owner flags"
# Read the flags and drive tar from python. Two of them are the EMPTY
# STRING (--uname "" --gname ""), which no amount of shell word-splitting
# can carry, so re-parsing them in sh would silently test a different
# command than the builder runs.
if python3 - "$WORK" <<'PY'
import subprocess, sys, tarfile, os, pathlib
work = sys.argv[1]
out = subprocess.run(["bash", "packaging/build-linux-tarballs.sh",
                      "--print-tar-owner-flags"],
                     capture_output=True, text=True)
flags = out.stdout.split("\n")[:-1]          # keeps the empty entries
if not flags:
    print("no flags printed"); sys.exit(2)
src = pathlib.Path(work, "src", "inner"); src.mkdir(parents=True, exist_ok=True)
(src / "f.txt").write_text("payload\n")
tgz = os.path.join(work, "clean.tar.gz")
subprocess.run(["tar", *flags, "-czf", tgz, "-C", os.path.join(work, "src"), "inner"],
               check=True, env={**os.environ, "COPYFILE_DISABLE": "1"})
leaked = [f"{m.name}: uid={m.uid} gid={m.gid} uname={m.uname!r} gname={m.gname!r}"
          for m in tarfile.open(tgz).getmembers()
          if m.uid or m.gid or m.uname or m.gname]
if leaked:
    print("\n".join(leaked)); sys.exit(1)
PY
then
    ok "a tarball built with the builder's own flags carries no owner identity"
else
    bad "the builder's flags still leave owner metadata behind"
fi

echo "2. the upload gate"
# PRIVATE-ONLY FROM HERE, and this guard is why the public runner went
# red. scan-release-assets.sh and private-patterns.txt are DELIBERATELY
# stripped from the public export - publish-public.sh says "the scanner
# literally contains the private vocabulary it greps for" - and two
# SIBLING tests of that scanner (scan-release-assets-patterns.sh,
# leak-check-paths.sh) are stripped alongside it. This test was missed,
# so on the public repo it ran four checks against a file that is not
# there and reported them as gate failures. Invisible until the tar
# dialect cascade above was fixed and stopped masking it.
#
# Skipped rather than deleted from the export, because section 1 IS
# meaningful publicly: build-linux-tarballs.sh ships, and its owner
# flags are exactly the thing a public contributor could break. Same
# shape as the e2e suites' have_par2() guard - say so out loud, do not
# quietly pass.
if [ ! -f packaging/scan-release-assets.sh ]; then
    echo "  skip - packaging/scan-release-assets.sh is not in this checkout."
    echo "         It is publish tooling and is private-only, so the upload"
    echo "         gate cannot be exercised here. Section 1 above still ran."
    echo
    echo "passed: $PASS  failed: $FAIL"
    [ "$FAIL" -eq 0 ]
    exit
fi
# A leak the pattern scanner cannot see: an account name nobody listed.
#
# BUILT WITH python's tarfile, NOT by shelling out to tar, and that is
# not a style preference. This block used to pass `--uid --gid --uname
# --gname`, which is the BSDTAR spelling: build-linux-tarballs.sh picks
# between that and GNU's `--owner=0 --group=0 --numeric-owner` by
# sniffing `tar --version`, because the two dialects disagree. The test
# hardcoded one side of that same fork, so it only ever worked on a Mac -
# on the Linux runner GNU tar answers `unrecognized option '--uid'`, the
# fixture is never created, and the four checks below fail as a CASCADE
# off a missing file, none of them naming the real cause. Green on every
# developer box and red in CI from the day it was wired in. tarfile
# writes the member header fields directly, so there is no dialect to
# get wrong and the fixture is identical on either platform.
if ! python3 - "$WORK" <<'PY'
import sys, os, tarfile
work = sys.argv[1]
src = os.path.join(work, "src", "inner", "f.txt")
with tarfile.open(os.path.join(work, "leak-linux-x64.tar.gz"), "w:gz") as t:
    ti = t.gettarinfo(src, arcname="inner/f.txt")
    # The whole point of the fixture: an owner identity in the header.
    ti.uid, ti.gid, ti.uname, ti.gname = 1001, 1001, "runner", "docker"
    with open(src, "rb") as fh:
        t.addfile(ti, fh)
PY
then
    bad "could not build the leak fixture"
    echo; echo "passed: $PASS  failed: $FAIL"; exit 1
fi
cp "$WORK/clean.tar.gz" "$WORK/ok-linux-x64.tar.gz"

# Both fixtures must EXIST before the gate checks below mean anything.
# Without this a fixture that failed to build becomes four failures that
# all read as gate problems, which is how the dialect bug above went
# unread in CI logs.
for a in "$WORK/leak-linux-x64.tar.gz" "$WORK/ok-linux-x64.tar.gz"; do
    [ -s "$a" ] || { bad "fixture missing: $(basename "$a")"
                     echo; echo "passed: $PASS  failed: $FAIL"; exit 1; }
done

# Two things run BEFORE the owner gate. The scan-stamp check is one, and
# is stamped for below. The other is the release-account check, the very
# first thing the script does, which no runner and no developer box can
# satisfy - so a `gh` stub answers it and refuses every other subcommand,
# which also makes the upload line at the end of the script inert. Until
# 23 Aug 2026 there was no stub and this step had never once reached the
# gate: it reported "did not refuse" while the script had in fact stopped
# at `gh login ... is not nzbfast`.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'ENDOFGH'
#!/bin/sh
case "$*" in
    "api user --jq .login") echo nzbfast ;;
    *) echo "STUB gh refused: $*" >&2; exit 1 ;;
esac
ENDOFGH
chmod +x "$WORK/bin/gh"
PATH="$WORK/bin:$PATH"
export PATH

# The upload script refuses anything without a current scan stamp, and
# that check runs first, so stamp both fixtures or the owner gate is
# never reached and the test passes without having tested anything.
# SHOW THE SCANNER'S OWN WORDS ON FAILURE. This was `>/dev/null 2>&1`,
# and that is why the gate has been unreadable: scan-release-assets.sh
# has more than a dozen distinct `✗ CANNOT INSPECT` exits (missing
# tool, unreadable gzip, nothing unpacked, no binary found) and every
# one of them arrived here as the same eleven words. On the public
# runner both fixtures are refused while both pass on a developer Mac
# AND in a plain linux container, so the reason is something about that
# environment - and the reason was being thrown away at exactly the
# moment it was needed. A test that hides the diagnosis of its own
# failure costs more than the failure does.
for a in "$WORK/leak-linux-x64.tar.gz" "$WORK/ok-linux-x64.tar.gz"; do
    if ! out=$(bash packaging/scan-release-assets.sh "$a" 2>&1); then
        bad "the pattern scanner refused $(basename "$a") before the owner gate"
        printf '%s\n' "$out" | sed 's/^/         | /'
    fi
done

out=$(bash packaging/upload-release-assets.sh v0.0.0-test "$WORK/leak-linux-x64.tar.gz" 2>&1)
case "$out" in
    *"builder identity"*) ok "refuses a tarball naming the account that built it" ;;
    *UNSCANNED*)          bad "never reached the owner gate (no scan stamp)" ;;
    *) bad "did not refuse an owner-carrying tarball: $(echo "$out" | head -1)" ;;
esac

# And the clean one must pass the same gate, or it refuses every release.
# Asserted on reaching the upload line rather than on the ABSENCE of a
# complaint: absence is also what every early exit produces, which is how
# this read green while nothing had run.
out=$(bash packaging/upload-release-assets.sh v0.0.0-test "$WORK/ok-linux-x64.tar.gz" 2>&1)
case "$out" in
    *"builder identity"*|*"names the account"*) bad "refused a clean tarball" ;;
    *"uploading to v0.0.0-test"*) ok "a clean tarball passes every gate" ;;
    *) bad "a clean tarball never reached the upload: $(echo "$out" | head -1)" ;;
esac

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
