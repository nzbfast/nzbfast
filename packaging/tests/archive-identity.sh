#!/bin/sh
# packaging/check-archive-identity.py: the builder-identity gate over
# every archive format release.yml ships.
#
# The leak this exists for is not hypothetical twice over. Cutting 1.1.3
# the FreeBSD tarball came out of its VM with `uid=0 gid=1001
# uname='root' gname=''` on every member and upload-release-assets.sh
# refused the batch; auditing the rest afterwards found the .qpkg on the
# PUBLISHED release carrying `uname='runner'` on every member of both its
# inner tars, which both of that script's gates skipped by name because a
# .qpkg is a shell script rather than an archive. Its macOS-metadata gate
# reaches inside one now (packaging/tests/qpkg-junk-gate.sh); its OWNER
# gate still cannot, because root:root is the correct ownership for a
# package format and that loop demands empty name strings. This is what
# holds the .qpkg to the right rule.
#
# What makes this class hard to see, and why every assertion below reads
# stored HEADERS rather than a listing:
#
#   - `tar tzvf` on the release Mac reports an owner-carrying tarball
#     without complaint, and CONSUMES AppleDouble members on read, so a
#     tarball with five junk entries lists clean. That is how v1.1.2
#     shipped them.
#   - packaging/scan-release-assets.sh catches a leak only when the
#     literal name is in private-patterns.txt. Built anywhere else - a CI
#     runner, a VM, a new machine - the same omission writes `runner` or
#     `root`, which no pattern knows.
#   - Extracting a .qpkg to look inside DROPS the uid/gid, because a
#     non-root tar cannot restore them. The check has to read the
#     archive, not a tree unpacked from it.
#
# Needs nothing installed: every fixture is built here.
#
# Run: packaging/tests/archive-identity.sh
set -u

cd "$(dirname "$0")/../.." || exit 1
CHECK=packaging/check-archive-identity.py
PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Every fixture is written by python's tarfile/zipfile, never by the
# system tar: the owner fields are set explicitly, so the test asserts
# what the checker reads rather than whatever the local tar felt like
# recording.
python3 - "$WORK" <<'PY'
import io, os, struct, sys, tarfile, zipfile

work = sys.argv[1]
payload = b"nzbfast\n" * 64


def member(name, uid=0, gid=0, uname="", gname=""):
    ti = tarfile.TarInfo(name)
    ti.size = len(payload)
    ti.uid, ti.gid, ti.uname, ti.gname = uid, gid, uname, gname
    return ti


def write_tar(path, owner, names=("nzbfast-1.0.0-linux-x64/nzbfast",)):
    with tarfile.open(path, "w:gz") as t:
        for n in names:
            t.addfile(member(n, *owner), io.BytesIO(payload))


CLEAN = (0, 0, "", "")
RUNNER = (1001, 1001, "runner", "docker")
# What the 1.1.3 FreeBSD tarball actually carried: uid 0, but a gid and a
# user name all the same. A checker keyed on uid alone waves it through.
FREEBSD_1_1_3 = (0, 1001, "root", "")

write_tar(f"{work}/clean-linux-x64.tar.gz", CLEAN)
write_tar(f"{work}/leak-linux-x64.tar.gz", RUNNER)
write_tar(f"{work}/freebsd-x64-beta.tar.gz", FREEBSD_1_1_3)
write_tar(f"{work}/appledouble-linux-x64.tar.gz", CLEAN,
          names=("nzbfast-1.0.0-linux-x64/nzbfast",
                 "._nzbfast-1.0.0-linux-x64"))

# A .spk is a tar of a tar: the leak can be one layer down, and a checker
# that stops at the outer members never sees it.
inner = f"{work}/package.tgz"
write_tar(inner, RUNNER, names=("nzbfast",))
with tarfile.open(f"{work}/nested-noarch.spk", "w") as t:
    ti = tarfile.TarInfo("package.tgz")
    ti.size = os.path.getsize(inner)
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    with open(inner, "rb") as fh:
        t.addfile(ti, fh)
os.remove(inner)

with zipfile.ZipFile(f"{work}/clean.zip", "w") as z:
    z.writestr("nzbfast-windows/nzbfast.exe", payload)
with zipfile.ZipFile(f"{work}/macjunk.zip", "w") as z:
    z.writestr("nzbfast-mac/nzbfast", payload)
    z.writestr("__MACOSX/nzbfast-mac/._nzbfast", b"\x00")


def ar(path, members):
    with open(path, "wb") as fh:
        fh.write(b"!<arch>\n")
        for name, body in members:
            fh.write(f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}"
                     f"{len(body):<10}".encode() + b"\x60\x0a")
            fh.write(body + (b"\n" if len(body) % 2 else b""))


def deb(path, owner):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        t.addfile(member("./usr/bin/nzbfast", *owner), io.BytesIO(payload))
    ar(path, [("debian-binary", b"2.0\n"), ("data.tar.gz", buf.getvalue())])


ROOT = (0, 0, "root", "root")
deb(f"{work}/clean_1.0.0_amd64.deb", ROOT)
deb(f"{work}/leak_1.0.0_amd64.deb", RUNNER)


def rpm(path, user, group):
    """A header-only .rpm: lead, signature header, main header.

    Enough of rpm(5) for the tags the checker reads. The parser was also
    run against the two real .rpm assets on the 1.1.3 release, and the
    `packages` job in release.yml runs it on freshly built ones every
    release - so this fixture covers the VERDICT, not the format.
    """
    def hdr(entries):
        index, store = b"", b""
        for tag, typ, vals in entries:
            index += struct.pack(">IIII", tag, typ, len(store), len(vals))
            for v in vals:
                store += v.encode() + b"\x00"
        return (b"\x8e\xad\xe8\x01" + b"\x00" * 4
                + struct.pack(">II", len(entries), len(store)) + index + store)

    sig = hdr([(1000, 6, ["x"])])
    main = hdr([(1117, 8, ["nzbfast"]), (1039, 8, [user]), (1040, 8, [group])])
    lead = b"\xed\xab\xee\xdb" + b"\x00" * 92
    pad = b"\x00" * ((8 - (len(sig) % 8)) % 8)
    open(path, "wb").write(lead + sig + pad + main)


rpm(f"{work}/clean-1.0.0.x86_64.rpm", "root", "root")
rpm(f"{work}/leak-1.0.0.x86_64.rpm", "runner", "docker")


# The .qpkg fixture builder is shared with packaging/tests/qpkg-junk-gate.sh,
# which needs the identical shape for the macOS-metadata gate. It used to
# be a second copy of it here; these scripts are copy-paste descendants of
# each other and this repo has twice had one rot away from its sibling.
#
# Its default data set carries an `nzbfast-*` member on purpose:
# scan-release-assets.sh refuses a .qpkg whose data archive holds no
# binary - "it unpacked" is not proof the payload was reached - and step 6
# runs that scanner for real, so the fixture has to satisfy it or the
# identity gate is never reached.
sys.path.insert(0, "packaging/tests")
from qpkg_fixture import build as build_qpkg          # noqa: E402

build_qpkg(f"{work}/clean-qnap-beta.qpkg", owner=(0, 0, "root", "root"))
build_qpkg(f"{work}/leak-qnap-beta.qpkg", owner=RUNNER)
open(f"{work}/notes.txt", "w").write("not an archive\n")
PY
[ $? -eq 0 ] || { echo "  FAIL - could not build the fixtures"; exit 1; }

# $1 = fixture, $2 = expect pass|refuse, $3 = what it proves
expect() {
    out=$(python3 "$CHECK" "$WORK/$1" 2>&1)
    rc=$?
    if [ "$2" = pass ] && [ $rc -eq 0 ]; then
        ok "$3"
    elif [ "$2" = refuse ] && [ $rc -ne 0 ]; then
        ok "$3"
    else
        bad "$3 (exit $rc)"
        echo "$out" | sed 's/^/         /'
    fi
}

echo "1. tar assets, held to uid/gid 0 and EMPTY names"
expect clean-linux-x64.tar.gz         pass   "a clean tarball passes"
expect leak-linux-x64.tar.gz          refuse "refuses uname='runner'"
expect freebsd-x64-beta.tar.gz        refuse "refuses the exact 1.1.3 FreeBSD shape (uid 0, gid 1001, 'root')"
expect appledouble-linux-x64.tar.gz   refuse "refuses a top-level AppleDouble member"
expect nested-noarch.spk              refuse "refuses a leak one layer down, inside a nested tar"

echo "2. zip"
expect clean.zip                      pass   "a clean zip passes"
expect macjunk.zip                    refuse "refuses __MACOSX/ and ._ members"

echo "3. .deb and .rpm, where root:root is CORRECT and anything else is a leak"
expect clean_1.0.0_amd64.deb          pass   "a root:root .deb passes"
expect leak_1.0.0_amd64.deb           refuse "refuses a .deb owned by the build account"
expect clean-1.0.0.x86_64.rpm         pass   "a root:root .rpm passes"
expect leak-1.0.0.x86_64.rpm          refuse "refuses FILEUSERNAME='runner'"

echo "4. .qpkg - the format the upload script's OWNER gate skips by name"
expect clean-qnap-beta.qpkg           pass   "a root:root .qpkg passes"
expect leak-qnap-beta.qpkg            refuse "refuses the leak that SHIPPED in 1.1.3"

echo "5. unopenable is not clean"
printf 'not a tarball at all' > "$WORK/broken-linux-x64.tar.gz"
expect broken-linux-x64.tar.gz        refuse "refuses an archive it cannot open"
expect notes.txt                      pass   "ignores a file that is not an archive"

echo "6. the upload gate carries it"
# Two things run BEFORE the identity gate and both have to be satisfied
# or this step passes on the wrong refusal:
#   - the release-account check, which is the very first thing the script
#     does and which no runner and no developer box can satisfy. A `gh`
#     stub answers it, and refuses every other subcommand, so the upload
#     line at the end of the script cannot do anything either. Without
#     this the step reported "did not refuse" while the script had in
#     fact stopped at `gh login ... is not nzbfast` - which it did on
#     every run of this test from the day it landed until 23 Aug 2026.
#   - the scan-stamp check, hence the scan below.
# PRIVATE-ONLY FROM HERE, same reason as the sibling guard in
# packaging/tests/linux-tarballs.sh: scan-release-assets.sh is
# DELIBERATELY stripped from the public export (publish-public.sh - "the
# scanner literally contains the private vocabulary it greps for"), and
# so is private-patterns.txt. Sections 1 to 5 above need neither and are
# meaningful publicly, which is why this skips rather than the whole
# file being pulled from the export.
#
# Found the same way and on the same day: the linux-tarballs cascade was
# masking it, and when that was fixed THIS became the next failure in
# the same job - 15 passed, 2 failed, both of them here.
if [ ! -f packaging/scan-release-assets.sh ]; then
    echo "  skip - packaging/scan-release-assets.sh is not in this checkout."
    echo "         It is publish tooling and is private-only, so the upload"
    echo "         gate cannot be exercised here. Sections 1-5 above still ran."
    echo
    echo "passed: $PASS  failed: $FAIL"
    [ "$FAIL" -eq 0 ]
    exit
fi
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
cp "$WORK/leak-qnap-beta.qpkg" "$WORK/nzbfast-0.0.0-qnap-beta.qpkg"
bash packaging/scan-release-assets.sh "$WORK/nzbfast-0.0.0-qnap-beta.qpkg" >/dev/null 2>&1 \
    || bad "the pattern scanner refused the .qpkg fixture before the identity gate"
out=$(bash packaging/upload-release-assets.sh v0.0.0-test \
        "$WORK/nzbfast-0.0.0-qnap-beta.qpkg" 2>&1)
case "$out" in
    *"builder identity"*) ok "upload-release-assets.sh refuses the .qpkg it used to wave through" ;;
    *UNSCANNED*)          bad "never reached the identity gate (no scan stamp)" ;;
    *) bad "did not refuse a leaking .qpkg: $(echo "$out" | head -1)" ;;
esac

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
