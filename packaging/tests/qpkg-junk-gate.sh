#!/bin/sh
# packaging/upload-release-assets.sh's macOS-metadata gate, over the one
# asset type it used to skip: the .qpkg.
#
# That gate refuses any archive carrying AppleDouble `._name` members or
# a `__MACOSX/` prefix, because `._name` at the top level is a SECOND
# top-level entry and every unpacker that collapses a lone wrapper
# directory keys on there being exactly one. v1.1.2 shipped both Linux
# tarballs that way and the Proxmox install could not start the service.
#
# A .qpkg is a self-extracting shell script, not an archive, so it was
# excluded by name with the reason written in the code and TODO 173
# carrying it as a known gap. packaging/qnap/unpack-qpkg.sh closes it -
# the same splitter packaging/scan-release-assets.sh has always used.
#
# The trap this test exists to pin: the splitter is asked for --parts,
# the two inner archives THEMSELVES, and not for an unpacked tree.
# bsdtar CONSUMES AppleDouble members on extract, so a gate that unpacked
# the package on the release Mac and walked the tree would report every
# junk-carrying .qpkg clean. Step 4 below shows that happening.
#
# Needs nothing installed: every fixture is built here.
#
# Run: packaging/tests/qpkg-junk-gate.sh
set -u

cd "$(dirname "$0")/../.." || exit 1
UPLOAD=packaging/upload-release-assets.sh
UNPACK=packaging/qnap/unpack-qpkg.sh
PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The upload script is zsh on the release Mac. Run it under zsh where
# there is one and bash otherwise - the gate uses arrays, which the two
# spell the same way, and a Linux runner without zsh must still test it.
RUNNER=$(command -v zsh 2>/dev/null || echo bash)

python3 - "$WORK" <<'ENDOFPY'
import sys

sys.path.insert(0, "packaging/tests")
from qpkg_fixture import DATA_NAMES, build          # noqa: E402

work = sys.argv[1]

build(f"{work}/nzbfast-0.0.0-qnap-clean.qpkg")
# The junk in the DATA archive, which is where a Mac-built payload would
# put it: one AppleDouble sibling per file carrying an xattr.
build(f"{work}/nzbfast-0.0.0-qnap-datajunk.qpkg",
      data_names=DATA_NAMES + ("./._nzbfast-x86_64",))
# ...and one layer further down, inside the control tar's nested .tgz.
# A checker that stops at the outer members never sees this one.
build(f"{work}/nzbfast-0.0.0-qnap-ctrljunk.qpkg",
      control_names=("./qpkg.cfg", "./._qpkg.cfg"))
# Not a QDK package at all: no script_len/offset header, so the splitter
# cannot find the boundaries and the gate has nothing to look at.
with open(f"{work}/nzbfast-0.0.0-qnap-broken.qpkg", "wb") as fh:
    fh.write(b"#!/bin/sh\necho not a qdk package\n" + b"\x00" * 4096)

# A .spk carrying the SAME shape - junk at the top level of a nested
# archive - for the reason step 5 gives.
import io, tarfile                                   # noqa: E402
from qpkg_fixture import APPLEDOUBLE, PAYLOAD        # noqa: E402

inner = io.BytesIO()
with tarfile.open(fileobj=inner, mode="w:gz") as t:
    for n, body in (("nzbfast", PAYLOAD), ("._nzbfast", APPLEDOUBLE)):
        ti = tarfile.TarInfo(n)
        ti.size = len(body)
        t.addfile(ti, io.BytesIO(body))
with tarfile.open(f"{work}/nzbfast-0.0.0-noarch.spk", "w") as t:
    ti = tarfile.TarInfo("package.tgz")
    ti.size = len(inner.getvalue())
    t.addfile(ti, io.BytesIO(inner.getvalue()))
ENDOFPY
[ $? -eq 0 ] || { echo "  FAIL - could not build the fixtures"; exit 1; }

# A `gh` that answers the login check and refuses everything else. Two
# jobs: it lets the test past the release-account check that is the very
# first thing the upload script does (and which no runner can satisfy),
# and it makes an actual upload impossible - a clean fixture reaches the
# `gh release upload` line, and that line must not do anything.
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

# Stamps are written by hand rather than by running the pattern scanner.
# The scan-stamp gate runs FIRST and would swallow every case below with
# UNSCANNED; what is under test here is the gate after it. That the real
# scanner accepts a .qpkg fixture is proved in archive-identity.sh.
stamp() {
    sum=$( { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; } | awk '{print $1; exit}' )
    echo "$sum  $(basename "$1")" >> "$WORK/.scan-stamps"
}
for q in "$WORK"/*.qpkg "$WORK"/*.spk; do stamp "$q"; done

# $1 = fixture, $2 = expected substring, $3 = what it proves
expect() {
    out=$("$RUNNER" "$UPLOAD" v0.0.0-test "$WORK/$1" 2>&1)
    case "$out" in
        *"$2"*) ok "$3" ;;
        *UNSCANNED*) bad "$3 - never reached the gate (no scan stamp)" ;;
        *) bad "$3"; echo "$out" | sed 's/^/         /' ;;
    esac
}

echo "1. the splitter hands back the parts, and extracts nothing"
rm -rf "$WORK/parts"
if "$UNPACK" --parts "$WORK/nzbfast-0.0.0-qnap-clean.qpkg" "$WORK/parts" >/dev/null 2>&1 \
        && [ -s "$WORK/parts/control.tar" ] && [ -s "$WORK/parts/data.tar.gz" ]; then
    ok "--parts writes control.tar and data.tar.gz"
else
    bad "--parts did not write both inner archives"
fi
if [ -d "$WORK/parts/control" ] || [ -d "$WORK/parts/data" ]; then
    bad "--parts unpacked the package as well - that is the mode it is not"
else
    ok "--parts extracted nothing, so nothing was passed through the local tar"
fi
if "$UNPACK" "$WORK/nzbfast-0.0.0-qnap-clean.qpkg" "$WORK/tree" >/dev/null 2>&1 \
        && [ -f "$WORK/tree/data/nzbfast-x86_64" ]; then
    ok "the default mode still unpacks (scan-release-assets.sh's caller)"
else
    bad "the default extract mode regressed"
fi

echo "2. the gate, over a .qpkg"
expect nzbfast-0.0.0-qnap-clean.qpkg "uploading to v0.0.0-test" \
    "a clean .qpkg passes every gate and reaches the upload"
expect nzbfast-0.0.0-qnap-datajunk.qpkg "data.tar.gz: macOS metadata" \
    "refuses an AppleDouble member in the data archive, naming which part"
expect nzbfast-0.0.0-qnap-ctrljunk.qpkg "control.tar: macOS metadata" \
    "refuses one a layer down, inside the control tar's nested .tgz"

echo "3. unopenable is not clean"
expect nzbfast-0.0.0-qnap-broken.qpkg "CANNOT INSPECT" \
    "refuses a .qpkg the splitter cannot take apart"

echo "4. why it reads the parts and not an unpacked tree"
# The whole reason for --parts. On the release Mac bsdtar CONSUMES an
# AppleDouble member as it extracts - it is metadata for the file beside
# it, not a file - so it is absent from the unpacked tree and a
# tree-walking gate calls the package clean. The stored header is still
# there, and reading headers is the only view that sees it. Exactly the
# asymmetry that let v1.1.2 ship five of them in each Linux tarball with
# every inspection reporting clean.
#
# Asserted on the header rather than on what the local tar does with it,
# because that half is platform-specific (GNU tar keeps the file) and the
# gate has to be right on both.
rm -rf "$WORK/parts2"
"$UNPACK" --parts "$WORK/nzbfast-0.0.0-qnap-datajunk.qpkg" "$WORK/parts2" >/dev/null 2>&1
if python3 -c "
import sys, tarfile
names = [m.name for m in tarfile.open(sys.argv[1]).getmembers()]
sys.exit(0 if any(n.split('/')[-1].startswith('._') for n in names) else 1)
" "$WORK/parts2/data.tar.gz"; then
    ok "the raw part carries the member the extraction may swallow"
else
    bad "the raw part does not carry the AppleDouble member"
fi

echo "5. the nested-member hole the same gate had for every format"
# Judging the LABEL instead of the name: an inner member was tested as
# "package.tgz!._nzbfast", whose basename is that whole string, so junk
# at the TOP level of a nested archive - the second-top-level-entry case
# this gate exists for - never matched. Only a nested member inside a
# subdirectory did. Found while wiring the .qpkg in, and fixed there, so
# it is pinned here on the .spk shape that carried it too.
expect nzbfast-0.0.0-noarch.spk "macOS metadata" \
    "refuses a top-level AppleDouble member inside a .spk's package.tgz"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
