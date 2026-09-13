#!/bin/sh
# Build the QNAP package (.qpkg) from the static musl binaries already
# attached to the GitHub Release - the same trick make-spk.sh and
# push-image.sh use, so the package ships the exact released bits and
# needs no cross-compiler here.
#
#   packaging/qnap/make-qpkg.sh 1.1.2 [outdir] [port]
#
# The published tarballs are the ONLY payload source, and that is the
# whole point: they are the bytes SHA256SUMS.txt covers, so the binaries
# inside the package are the binaries anyone can check. Until 16 Aug 2026
# there was a second form, `--binaries <dir>`, which took the two musl
# binaries from a directory so that release.yml could build the package
# DURING the release run, before anything was on the release page. It
# worked, and it shipped a package nobody could verify: on 1.1.3 the
# packaged binaries were a separate CI cross-build of the same source
# (72cad10c / 71d12ee9) and matched neither tarball (9cc8c994 / a11ce1ac)
# nor any checksum published anywhere. The .qpkg is now built AFTER the
# release, from the release, like the Synology .spk - see the
# `qnap-qpkg` workflow and step 4c of the publish-release skill. Do not
# reintroduce a payload source the release page cannot vouch for.
#
# Produces ONE package, nzbfast-<ver>-qnap-beta.qpkg, carrying both the
# x86_64 and aarch64 binaries; nzbfast-setup.sh keeps the one this NAS can
# run and deletes the other. The reasoning for one file rather than one
# per architecture is in qpkg.cfg.
#
# BETA. Nobody on this team owns a QNAP, so nothing here has been proven
# on real hardware: the install decisions are tested off-box
# (packaging/tests/qnap-install.sh) and the built package is verified by
# taking it apart again below, but "it unpacks correctly" is not "it
# installs and runs". The filename says beta for that reason, and the
# package is deliberately NOT in the signed update manifest - see
# packaging/qnap/README.md.
#
# The build itself runs QDK, QNAP's own kit, pinned in qdk-pin.txt. It
# runs natively when qbuild is already on PATH, which is what CI does,
# and in a container on a Linux host without it. On macOS NEITHER path
# can work and this script refuses at the top - see the host check below
# for why, and dispatch the qnap-qpkg workflow instead.
set -eu

VER="${1:?usage: make-qpkg.sh <version> [outdir] [port]}"
OUTDIR="${2:-dist}"
# The port is baked in at build time because QTS reads Web_Port and
# Service_Port out of the package at install and cannot be told a
# different one later - App Center's Open button would point at the wrong
# place if the service picked a port dynamically. 6789 is right for
# essentially everyone; a different value exists so a second instance can
# be built for testing alongside a running one.
PORT="${3:-6789}"
REL="https://github.com/nzbfast/nzbfast/releases/download/v${VER}"
SELF="$(cd "$(dirname "$0")" && pwd)"
QDK_COMMIT="$(grep -v '^#' "$SELF/qdk-pin.txt" | grep -m1 . )"

# ---- host check -------------------------------------------------------
# macOS cannot build this package by EITHER path below, so refuse here -
# before downloading ~40 MB of payload, before starting a container
# runtime, before building the QDK image. Each of those fails later,
# somewhere else, and says something other than what is wrong.
#
#   Natively: qbuild finishes by rewriting the generated self-extractor
#   with `sed -i "s/SCRIPT_LEN/.../"`. BSD sed reads the next argument as
#   a backup suffix, so the length patch never lands and the package
#   cannot unpack itself. QDK is ~2,400 lines of GNU-assuming shell and
#   that call is only the first one to bite.
#
#   In a container: qbuild is fine in there - the STAGING TREE is not.
#   $WORK comes from `mktemp -d`, and macOS mktemp given no template
#   IGNORES $TMPDIR: it always returns /var/folders/<...>/T/tmp.XXXXXXXX,
#   from confstr(_CS_DARWIN_USER_TEMP_DIR). colima shares $HOME and
#   /tmp/colima into its VM and does not share /var/folders, so the bind
#   mount hands qbuild an EMPTY /work and it reports
#   `qpkg.cfg: No such file` about a file sitting in the staging tree on
#   the host. Re-running with TMPDIR under $HOME does not move it, which
#   is exactly what makes that message worth an hour. Diagnosed the long
#   way on 4 Sep 2026 cutting v1.4.0. The container path stays, for the
#   Linux hosts where it works.
#
# Do not hand-assemble the layout instead: qinstall.sh runs as ROOT on
# somebody's NAS, so the format is not something to guess at.
if [ "$(uname -s)" = "Darwin" ]; then
    cat >&2 <<EOF
✗ the .qpkg cannot be built on macOS, by any path this script has.

  qbuild natively: it patches its own self-extractor with
    sed -i "s/SCRIPT_LEN/.../"
  and BSD sed reads the next argument as a backup suffix, so the length
  patch never lands and the package cannot unpack itself.

  qbuild in a container: macOS \`mktemp -d\` ignores \$TMPDIR, so the
  staging tree is under /var/folders, which colima does not share into
  its VM. qbuild then sees an empty /work and says
    qpkg.cfg: No such file
  about a file that is right there on the host. Setting TMPDIR does not
  move it - that message is about the mount, not about qpkg.cfg.

  Build it in CI, on the Ubuntu runner where QDK works - dispatch on the
  private repo, which is where every other release workflow is run:

      TAG=v$VER
      gh workflow run qnap-qpkg.yml --ref "\$TAG" -f tag="\$TAG"

  \`--ref\` is load-bearing and the workflow refuses a dispatch without
  it: \`-f tag=\` selects only the PAYLOAD, while qpkg.cfg,
  package_routines and the pinned QDK qinstall.sh that runs as ROOT on
  the NAS all come from whatever the run checked out. Step 4c of the
  publish-release skill is the rest of it - the release page has to be
  up first, and the artifact is scanned and uploaded by hand.
EOF
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then SHA256C="sha256sum -c -"
else SHA256C="shasum -a 256 -c -"; fi

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

# ---- payload ----------------------------------------------------------
# Fetch + verify the released linux binaries. Each archive is checked
# against its OWN checksum line and that line has to exist, so a partial
# SHA256SUMS.txt cannot let an unverified binary into a package.
for a in linux-x64 linux-arm64; do
    curl -fsSL -o "$DIR/nzbfast-$VER-$a.tar.gz" "$REL/nzbfast-$VER-$a.tar.gz"
done
curl -fsSL -o "$DIR/SHA256SUMS.txt" "$REL/SHA256SUMS.txt"
for a in linux-x64 linux-arm64; do
    art="nzbfast-$VER-$a.tar.gz"
    n=$(grep -c "[ *]$art\$" "$DIR/SHA256SUMS.txt" || true)
    if [ "$n" != "1" ]; then
        echo "✗ SHA256SUMS.txt has $n checksum lines for $art (need exactly 1)" >&2
        exit 1
    fi
    (cd "$DIR" && grep "[ *]$art\$" SHA256SUMS.txt | $SHA256C)
done

# ---- staging ----------------------------------------------------------
# A QDK build root: qpkg.cfg and package_routines at the top, shared/
# holding everything that lands in the installed package directory, and
# icons/ named after the package. Built in a temp copy so the repo never
# holds a version- or port-substituted file.
WORK="$DIR/build"
mkdir -p "$WORK/shared/bin" "$WORK/icons"
cp "$SELF/qpkg.cfg" "$SELF/package_routines" "$WORK/"
cp "$SELF/shared/nzbfast.sh" "$SELF/shared/nzbfast-setup.sh" "$WORK/shared/"
cp "$SELF/icons/nzbfast.png" "$SELF/icons/nzbfast_80.png" \
   "$SELF/icons/nzbfast_gray.png" "$WORK/icons/"

# linux-x64 -> x86_64, linux-arm64 -> aarch64. These are the names
# nzbfast-setup.sh looks for; they are not our release-asset names.
for pair in "linux-x64 x86_64" "linux-arm64 aarch64"; do
    asset=${pair% *}; arch=${pair#* }
    tar xzf "$DIR/nzbfast-$VER-$asset.tar.gz" -C "$DIR" "nzbfast-$VER-$asset/nzbfast"
    cp "$DIR/nzbfast-$VER-$asset/nzbfast" "$WORK/shared/bin/nzbfast-$arch"
    chmod 755 "$WORK/shared/bin/nzbfast-$arch"
done

# They have to be STATIC, and the checksum above does not say so - it
# says the tarball is the one that was released. A binary linked
# against a build host's glibc does not start on a NAS (measured 28 Jul:
# GLIBC_2.39 not found on debian:bookworm, and QTS is older than that),
# and the failure is a package that installs cleanly and never runs.
# upload-release-assets.sh enforces the same rule for the human tarballs.
# Assert the positive. This used to reject only when `file` was present
# AND said "dynamically linked", so every other way of being wrong went
# through: no file(1) on the box, a text file, an empty file, or the
# right linkage on the WRONG ARCHITECTURE - an aarch64 binary shipped as
# nzbfast-x86_64 passes a linkage-only check and fails on the NAS, which
# is the failure this gate exists to prevent.
command -v file >/dev/null 2>&1 || {
    echo "✗ file(1) is not installed, so the packaged binaries cannot be" >&2
    echo "  checked. Refusing rather than shipping an unverified .qpkg." >&2
    exit 1
}
for arch in x86_64 aarch64; do
    f="$WORK/shared/bin/nzbfast-$arch"
    desc=$(file -b "$f" 2>/dev/null || true)
    case "$desc" in
        *"statically linked"*) ;;
        *)
            echo "✗ $f is not a statically linked binary." >&2
            echo "  file says: ${desc:-<nothing>}" >&2
            echo "  The package needs the static musl build, not a glibc one." >&2
            exit 1
            ;;
    esac
    case "$arch" in
        x86_64)  want="x86-64" ;;
        aarch64) want="aarch64" ;;
    esac
    case "$desc" in
        *"$want"*) ;;
        *)
            echo "✗ $f is not a $arch binary - file says: $desc" >&2
            echo "  The two binaries are picked by name at install time, so" >&2
            echo "  a swapped pair installs cleanly and never starts." >&2
            exit 1
            ;;
    esac
done
chmod 755 "$WORK/shared/nzbfast.sh" "$WORK/shared/nzbfast-setup.sh"

# Bake in the version and the port. Anything still holding a placeholder
# afterwards is a file someone added without wiring it up, so fail loudly
# rather than shipping a package with "@@PORT@@" where a port belongs.
for f in "$WORK/qpkg.cfg" "$WORK/package_routines" \
         "$WORK/shared/nzbfast.sh" "$WORK/shared/nzbfast-setup.sh"; do
    sed -e "s/@@PORT@@/$PORT/g" -e "s/@@VERSION@@/$VER/g" "$f" > "$f.tmp"
    mv "$f.tmp" "$f"
done
chmod 755 "$WORK/shared/nzbfast.sh" "$WORK/shared/nzbfast-setup.sh"
if grep -rl "@@PORT@@\|@@VERSION@@" "$WORK" 2>/dev/null | grep -q .; then
    echo "✗ unsubstituted placeholder left in:" >&2
    grep -rl "@@PORT@@\|@@VERSION@@" "$WORK" >&2
    exit 1
fi

# ---- build ------------------------------------------------------------
# --gzip: the data archive stays a plain tar.gz. QDK also offers 7z and
# xz, both of which make the package depend on an extractor being present
# on the NAS, and both of which would put the shipped binaries out of
# reach of packaging/scan-release-assets.sh - a leak gate that cannot open
# an asset is a gate that passes it blind.
QBUILD_ARGS="--root $WORK --build-dir $WORK/out --build-version $VER --gzip --verbose"

# QDK has to be told where it lives. qbuild works out a default QDK_PATH
# from its own location and then sources qdk.conf, which overwrites it
# with a value derived from the CURRENT DIRECTORY:
#     QDK_PATH_P=`pwd | awk 'BEGIN { FS = "QDK" } ; { print $1 }'`
# That resolves to <cwd>/QDK, which is right only when you happen to be
# building from inside a directory tree named QDK, and is why a checkout
# anywhere else fails with "<repo>/QDK/scripts/qinstall.sh: no such
# file". QDK_SCRIPTS_DIR and QDK_TEMPLATE_DIR are read from the
# environment before that default is applied, so setting them is the
# supported way past it.
qdk_env_from_qbuild() {
    _qb="$1"
    _share=$(dirname "$(dirname "$(readlink -f "$_qb" 2>/dev/null || echo "$_qb")")")
    QDK_SCRIPTS_DIR="${QDK_SCRIPTS_DIR:-$_share/scripts}"
    QDK_TEMPLATE_DIR="${QDK_TEMPLATE_DIR:-$_share/template}"
    export QDK_SCRIPTS_DIR QDK_TEMPLATE_DIR
    if [ ! -f "$QDK_SCRIPTS_DIR/qinstall.sh" ]; then
        echo "✗ $QDK_SCRIPTS_DIR/qinstall.sh is not there." >&2
        echo "  qbuild at $_qb does not look like a QDK checkout. Point" >&2
        echo "  QDK_SCRIPTS_DIR and QDK_TEMPLATE_DIR at one." >&2
        exit 1
    fi
    # qbuild's last step stamps a checksum into the package trailer with
    # qpkg_encrypt, a small C program that lives in QDK's src/ and is NOT
    # built by cloning. Missing, qbuild prints one "command not found"
    # line among its progress messages and still exits 0, leaving a
    # package whose checksum field is blank - which App Center is the one
    # to discover. Refuse here instead.
    if ! command -v qpkg_encrypt >/dev/null 2>&1; then
        echo "✗ qpkg_encrypt is not on PATH." >&2
        echo "  It is QDK's own checksum tool and has to be compiled:" >&2
        echo "      make -C <qdk-checkout>/src" >&2
        echo "  then put <qdk-checkout>/src/bin on PATH. Without it" >&2
        echo "  qbuild still writes a .qpkg, and the checksum field in" >&2
        echo "  its trailer is left blank." >&2
        exit 1
    fi
}

# Owner metadata. qbuild tars $WORK with a plain `tar`, so every member
# of both the control archive and the data archive records the account
# that ran the build. On a CI runner that is `uid=1001 gid=1001
# uname='runner' gname='runner'`, and the 1.1.3 package shipped exactly
# that on every entry - a builder identity in a project that is anonymous
# in public, in a field App Center never displays.
#
# Neither of upload-release-assets.sh's two archive gates catches it: a
# .qpkg is a self-extracting shell script rather than an archive, so both
# skip it by name. packaging/check-archive-identity.py is what looks
# inside one, and this is the fix at the source it exists to enforce.
#
# fakeroot is how a package build gets root:root without being root, and
# root:root is also the correct INSTALLED ownership for a NAS package -
# the same end dpkg-deb reaches with --root-owner-group in
# packaging/linux/make-packages.sh. The chown has to run inside the SAME
# fakeroot session as qbuild: the faked ownership lives in that session's
# map, so a chown before it or a tar after it sees the real uid.
if command -v qbuild >/dev/null 2>&1; then
    echo "building with qbuild on PATH ($(command -v qbuild))"
    qdk_env_from_qbuild "$(command -v qbuild)"
    if ! command -v fakeroot >/dev/null 2>&1; then
        echo "✗ fakeroot is not installed." >&2
        echo "  Without it qbuild stamps the building account's uid, gid" >&2
        echo "  and user name into every member of the package's two" >&2
        echo "  inner tars, and nothing downstream looks: the .qpkg is a" >&2
        echo "  shell script, so the upload gates skip it. Install it" >&2
        echo "  (apt-get install fakeroot) and re-run." >&2
        exit 1
    fi
    # shellcheck disable=SC2086  # deliberate word splitting of the args
    fakeroot sh -c "chown -R 0:0 '$WORK' && qbuild $QBUILD_ARGS"
elif command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
    RUNTIME=docker
    command -v docker >/dev/null 2>&1 || RUNTIME=podman
    echo "building with QDK in a $RUNTIME container (QDK $QDK_COMMIT)"
    $RUNTIME build -q -t "nzbfast-qdk:$QDK_COMMIT" \
        --build-arg "QDK_COMMIT=$QDK_COMMIT" "$SELF" >/dev/null
    # The staging directory is the only thing mounted, and qbuild runs as
    # the container's root over a copy - the repo is never in scope.
    # chown for the same reason the fakeroot branch above does one. qbuild
    # runs as the container's root, but $WORK is a BIND MOUNT: the files
    # keep the host account's numeric uid/gid, which tar then writes into
    # every header (with no matching name, so it reads as a bare number
    # rather than looking like a leak). $WORK is a mktemp staging tree
    # this script owns and deletes, so chowning it costs nothing.
    # The `qpkg.cfg: No such file` qbuild prints when the mount did not
    # land names a file that IS in the staging tree, and says nothing
    # about which side was empty. Look before building so the message
    # names the mount instead.
    # shellcheck disable=SC2016  # the ls runs INSIDE the container
    $RUNTIME run --rm -v "$WORK:/work" "nzbfast-qdk:$QDK_COMMIT" \
        sh -c 'if [ ! -f /work/qpkg.cfg ]; then
                   echo "✗ /work does not hold qpkg.cfg." >&2
                   echo "  It holds: $(ls -A /work 2>/dev/null | tr "\n" " ")" >&2
                   echo "  The staging tree is populated on the host, so this" >&2
                   echo "  runtime is not sharing that path into its VM." >&2
                   exit 1
               fi
               chown -R 0:0 /work && exec "$@"' _ \
        qbuild --root /work --build-dir /work/out --build-version "$VER" \
               --gzip --verbose
else
    echo "✗ no qbuild and no container runtime." >&2
    echo "  The .qpkg is built by QNAP's own QDK. Either:" >&2
    echo "    - put qbuild on PATH (see packaging/qnap/README.md), or" >&2
    echo "    - install Docker or Podman and re-run this - the Dockerfile" >&2
    echo "      beside this script builds the pinned QDK, or" >&2
    echo "    - let CI do it: the qnap-qpkg workflow builds the package" >&2
    echo "      on an Ubuntu runner. Dispatch it AT THE TAG:" >&2
    echo "          gh workflow run qnap-qpkg.yml --ref v$VER -f tag=v$VER" >&2
    echo "  Do not hand-assemble the package layout instead." >&2
    exit 1
fi

BUILT="$(ls "$WORK/out"/*.qpkg 2>/dev/null | head -1 || true)"
[ -n "$BUILT" ] || { echo "✗ qbuild produced no .qpkg" >&2; exit 1; }

# A non-default port means a test build, so say so in the filename. The
# shipped artifact must never be ambiguous about which port it claims,
# and these do get passed around by hand.
NAME="nzbfast-$VER-qnap-beta"
[ "$PORT" = "6789" ] || NAME="$NAME-port$PORT"
cp "$BUILT" "$OUTDIR/$NAME.qpkg"

# ---- verify -----------------------------------------------------------
# Take the package apart again and look inside. qbuild reports success
# for a build whose payload is empty, whose version was never
# substituted, or whose service script did not survive staging - and none
# of those can be caught by reading its output. This is the same recipe
# packaging/scan-release-assets.sh uses on the shipped asset.
"$SELF/unpack-qpkg.sh" "$OUTDIR/$NAME.qpkg" "$DIR/verify"
fail=0
check() {
    if [ -e "$DIR/verify/$2" ]; then echo "  ok   $1"
    else echo "  FAIL $1 (missing $2)" >&2; fail=1; fi
}
echo "verifying $NAME.qpkg:"
check "control: qpkg.cfg"          control/qpkg.cfg
check "control: package_routines"  control/package_routines
check "control: qinstall.sh"       control/qinstall.sh
check "payload: x86_64 binary"     data/bin/nzbfast-x86_64
check "payload: aarch64 binary"    data/bin/nzbfast-aarch64
check "payload: service script"    data/nzbfast.sh
check "payload: setup script"      data/nzbfast-setup.sh
if grep -q "^QPKG_VER=\"$VER\"" "$DIR/verify/control/qpkg.cfg" 2>/dev/null; then
    echo "  ok   control: version is $VER"
else
    echo "  FAIL control: qpkg.cfg does not carry version $VER" >&2; fail=1
fi
if grep -q "^QPKG_WEB_PORT=\"$PORT\"" "$DIR/verify/control/qpkg.cfg" 2>/dev/null; then
    echo "  ok   control: web port is $PORT"
else
    echo "  FAIL control: qpkg.cfg does not carry port $PORT" >&2; fail=1
fi
# The 100-byte trailer is what App Center reads to identify the package:
#   [MODEL(10)|RESERVED(40)|FW_VERSION(10)|NAME(20)|VERSION(10)|FLAG(10)]
# qbuild appends it, then qpkg_encrypt overwrites ten bytes 60 from the
# end with the checksum. Both are silent when they do not happen.
TRAILER=$(tail -c 100 "$OUTDIR/$NAME.qpkg" | LC_ALL=C tr -d '\000')
case "$TRAILER" in
    *QNAPQPKG*) echo "  ok   trailer: carries the QNAPQPKG marker" ;;
    *) echo "  FAIL trailer: no QNAPQPKG marker - App Center reads this" >&2; fail=1 ;;
esac
case "$TRAILER" in
    *"$VER"*) echo "  ok   trailer: names version $VER" ;;
    *) echo "  FAIL trailer: does not name version $VER" >&2; fail=1 ;;
esac
ENC=$(tail -c 60 "$OUTDIR/$NAME.qpkg" | head -c 10 | LC_ALL=C tr -d ' \000')
if [ -n "$ENC" ]; then
    echo "  ok   trailer: checksum field is stamped"
else
    echo "  FAIL trailer: checksum field is blank - qpkg_encrypt did not run" >&2
    fail=1
fi
if grep -rq "@@PORT@@\|@@VERSION@@" "$DIR/verify" 2>/dev/null; then
    echo "  FAIL a placeholder survived into the package" >&2; fail=1
else
    echo "  ok   no unsubstituted placeholders"
fi
[ "$fail" = 0 ] || { echo "✗ the built package is not what it should be." >&2; exit 1; }

echo
echo "built $OUTDIR/$NAME.qpkg ($(du -h "$OUTDIR/$NAME.qpkg" | cut -f1), port $PORT)"
echo
echo "install: App Center → the gear icon → Install Manually → this file."
echo "         QTS will warn that it is not from the App Center. It is a"
echo "         BETA nobody has been able to run on real hardware yet."
