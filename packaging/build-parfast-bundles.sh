#!/usr/bin/env bash
# build-parfast-bundles.sh [dist-dir] [arch...]
#
# Build the parfast release assets. parfast is the par2cmdline-dialect
# CLI over nzbfast's PAR2 engine (crates/parfast), and this is the ONLY
# thing that packages it - nothing else in packaging/ knows it exists.
#
# WHY A SCRIPT OF ITS OWN, and not `-p parfast` bolted onto the existing
# ones. The nzbfast release assets are a daemon with a web UI installed
# as a service: a DMG with a WKWebView wrapper, per-user installers, deb
# and rpm service packages, NAS app packages, updater payloads and a
# signed manifest. parfast is a single executable somebody runs in a
# terminal. It shares none of that machinery, and threading a second
# product through scripts built for the first buys a `if [ "$prod" = ]`
# in every one of them. Design record:
# research/SPEC-PARFAST-PUBLICATION-2026-09-10.md.
#
#   dist-dir   where the assets land (default ./dist-parfast)
#   arch...    a subset of: macos-universal windows-x64 linux-x64
#              linux-arm64 linux-armv7 freebsd-x64
#              (default: the first four; the last two are extras that
#              need their own toolchains and are built on request)
#
# NO ASSET WEARS `-beta` ANY MORE, AND THAT IS THE 1.6.0 CHANGE. Until
# then every filename carried one, for this repo's existing convention,
# carried from the armv7 tarball, whose own header still states the
# reason: the release notes are one page a downloader may never read,
# and an asset list is the thing they actually click. parfast's version
# tracks nzbfast's (decision D3), so the version string alone could not
# say "first release, not yet proven" - the filename had to.
#
# parfast shipped stable at 1.6.0, so it says nothing of the sort now,
# and the machinery that spelled it is gone rather than set to an empty
# string: the `BETA_SUFFIX` case here appended `-beta` to any version
# WITHOUT a pre-release part, which is precisely what a stable 1.6.0 is,
# so leaving it in place would have shipped `parfast-1.6.0-macos-
# universal-beta.tar.gz` off a bump alone. An inert variable that is one
# `case` arm away from being wrong is worse than no variable.
#
# If parfast ever takes a pre-release again, the version string itself
# carries it (`1.7.0-rc.1`) and lands in `$VERSION` here with no edit -
# which is what the old case's first arm already did for `-beta.N`. The
# GUI is the live example: it is a beta at 1.6.0-beta.1 and its own
# bundler, apps/parfast/packaging/build-parfast-gui-bundles.sh, gets its
# stage from GUI_STAGE and needs no suffix logic either.
#
# Prereqs, by arch:
#   macos-universal  rustup target add aarch64-apple-darwin x86_64-apple-darwin
#   windows-x64      rustup target add x86_64-pc-windows-gnu; brew install mingw-w64
#   linux-*          cargo-zigbuild + zig  (same as build-linux-tarballs.sh)
#   freebsd-x64      cargo-zigbuild + the freebsd target
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

# Owner metadata, the same rule and the same spelling as
# build-linux-tarballs.sh. tar records the BUILDING ACCOUNT's uid, gid,
# user name and group name in every member header unless told not to,
# and this project is anonymous in public - so without these flags every
# member of every parfast tarball names the machine that cut it. This
# script shipped without them and nothing caught it, because parfast had
# never been through a release: the first run of
# packaging/check-archive-identity.py over its output (12 Sep 2026, the
# 1.5.0-beta.1 build) refused all three tarballs on `uname='<account>'`,
# and packaging/scan-release-assets.sh refused them on the same string.
# The zip arm was never affected - the format has no uid/gid/uname
# fields - which is exactly why a zip passing is no evidence for a
# tarball.
#
# The spelling differs by tar and both are in play (bsdtar on the
# release Mac, GNU tar on a Linux runner), so ask rather than assume:
# a wrong flag is a hard error mid-build, a missing one is a silent leak.
if tar --version 2>&1 | head -1 | grep -qi bsdtar; then
    TAR_OWNER=(--uid 0 --gid 0 --uname "" --gname "")
else
    TAR_OWNER=(--owner=0 --group=0 --numeric-owner)
fi

VERSION=$(grep -m1 '^version' crates/parfast/Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
[ -n "$VERSION" ] || { echo "cannot read parfast version" >&2; exit 1; }

DIST=${1:-dist-parfast}; shift || true
ARCHES=${*:-"macos-universal windows-x64 linux-x64 linux-arm64"}

mkdir -p "$DIST"; DIST=$(cd "$DIST" && pwd)

triple_of() {
    case $1 in
        linux-x64)    echo x86_64-unknown-linux-musl ;;
        linux-arm64)  echo aarch64-unknown-linux-musl ;;
        linux-armv7)  echo armv7-unknown-linux-musleabihf ;;
        freebsd-x64)  echo x86_64-unknown-freebsd ;;
        *) echo "" ;;
    esac
}

# The README that ships beside the binary. parfast has no manual and
# needs none - `parfast --help` is the reference and it is par2cmdline's
# - so this says what it is and where to complain. It said "this is a
# beta" until 1.6.0; what replaced that paragraph is not silence, it is
# the repair warning, which was always the half that mattered.
write_readme() {
    cat > "$1/README.txt" <<README
parfast $VERSION - PAR2 create, verify and repair

parfast makes, checks and repairs PAR2 recovery sets from the command
line. It takes par2cmdline's arguments and returns par2cmdline's exit
codes, so a script that calls par2 today can call parfast instead.

    parfast c set.par2 file1 file2 ...   create
    parfast v set.par2                   verify
    parfast r set.par2                   repair
    parfast --help                       the full reference

parfast has a full test suite and is checked command by command against
par2cmdline-turbo. Please tell us how you get on - hearing that it
worked is as useful to us as hearing that it did not.

Repairing rewrites files in place, which is what repairing is. Keep a
copy of anything you cannot lose, the same as with any other such tool.

Issues, and the source:  https://github.com/nzbfast/nzbfast
parfast's own source is in that repository under crates/parfast.

Licence: GPL-3.0-or-later. See LICENSE beside this file.
README
}

# Common payload for every asset: the binary is added by the caller.
stage_common() { cp LICENSE COPYRIGHT.md "$1/"; write_readme "$1"; }

for arch in $ARCHES; do
    echo "== $arch =="
    work=$(mktemp -d)
    inner="$work/parfast-$VERSION-$arch"
    mkdir -p "$inner"

    case $arch in
    macos-universal)
        for t in aarch64-apple-darwin x86_64-apple-darwin; do
            rustup target add "$t" >/dev/null 2>&1 || true
            # 11.0: the mac CLI floor. Unset, cc-rs compiles the C for
            # this Mac's own macOS (research/MAC-DEPLOYMENT-TARGET-2026-09-15.md).
            MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --locked -p parfast --target "$t"
        done
        lipo -create -output "$inner/parfast" \
            target/aarch64-apple-darwin/release/parfast \
            target/x86_64-apple-darwin/release/parfast
        # Assert the positive, the way build-linux-tarballs.sh does: a
        # `lipo -create` that silently produced a thin binary is a mac
        # asset that will not start on half the machines it is for.
        lipo -info "$inner/parfast" | grep -q 'arm64 x86_64\|x86_64 arm64' || {
            echo "✗ not a universal binary: $(lipo -info "$inner/parfast")" >&2; exit 1; }
        chmod +x "$inner/parfast"
        stage_common "$inner"
        asset="parfast-$VERSION-macos-universal.tar.gz"
        COPYFILE_DISABLE=1 tar "${TAR_OWNER[@]}" -czf "$DIST/$asset" -C "$work" "$(basename "$inner")"
        ;;
    windows-x64)
        rustup target add x86_64-pc-windows-gnu >/dev/null 2>&1 || true
        # Do NOT set CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS here.
        # `-static` and `--remap-path-prefix` both come from
        # .cargo/config.toml, and the env var REPLACES that list rather
        # than adding to it - which is exactly how the first v1.0.0 exe
        # shipped with the build host's home directory inside it.
        cargo build --release --locked -p parfast --target x86_64-pc-windows-gnu
        cp target/x86_64-pc-windows-gnu/release/parfast.exe "$inner/parfast.exe"
        # The check that trap earns. Must be zero. Greps for $HOME
        # rather than a literal path: the literal would itself be a
        # build-host path inside a file that ships publicly (the
        # pre-commit leak scan refuses exactly that, and did), and the
        # runtime form is the more correct check anyway - it catches the
        # remap being dropped on whatever machine is building.
        n=$(strings -a "$inner/parfast.exe" 2>/dev/null | grep -c "$HOME" || true)
        [ "$n" = 0 ] || { echo "✗ windows exe carries $n build-host path(s)" >&2; exit 1; }
        stage_common "$inner"
        asset="parfast-$VERSION-windows-x64.zip"
        ( cd "$work" && zip -q -r -X "$DIST/$asset" "$(basename "$inner")" )
        ;;
    linux-*|freebsd-*)
        triple=$(triple_of "$arch")
        [ -n "$triple" ] || { echo "unknown arch: $arch" >&2; exit 1; }
        command -v cargo-zigbuild >/dev/null 2>&1 || {
            echo "cargo-zigbuild not found - needed for $arch" >&2; exit 1; }
        rustup target add "$triple" >/dev/null 2>&1 || true
        cargo zigbuild --release --locked -p parfast --target "$triple"
        bin=target/$triple/release/parfast
        # Linux assets must be static or they will not start on the
        # distributions this download exists for. Assert the positive:
        # an unreadable `file` output fails here rather than passing by
        # failing to match a negative.
        case $arch in linux-*)
            file "$bin" | grep -q "statically linked" || {
                echo "✗ $triple: NOT statically linked - $(file -b "$bin")" >&2; exit 1; }
            ;;
        esac
        cp "$bin" "$inner/parfast"; chmod +x "$inner/parfast"
        stage_common "$inner"
        asset="parfast-$VERSION-$arch.tar.gz"
        # COPYFILE_DISABLE=1 is load-bearing on the release Mac: bsdtar
        # stores an AppleDouble `._name` member for any file carrying an
        # xattr, which yields a second top-level entry that breaks
        # unpackers collapsing a lone wrapper directory. v1.1.2 shipped
        # both linux tarballs that way, and `tar tzvf` ON A MAC lists
        # such a tarball clean - so do not "verify" it with tar here.
        COPYFILE_DISABLE=1 tar "${TAR_OWNER[@]}" -czf "$DIST/$asset" -C "$work" "$(basename "$inner")"
        ;;
    *)
        echo "unknown arch: $arch" >&2; exit 1 ;;
    esac

    rm -rf "$work"
    echo "  -> $DIST/$asset"
done

echo
echo "== parfast $VERSION =="
ls -lh "$DIST"
