#!/bin/sh
# Build the Synology DSM 7 package (.spk) from the static musl binaries
# already attached to the GitHub Release - the same trick push-image.sh
# uses, so the package ships the exact released bits and needs no
# cross-compiler here.
#
#   packaging/synology/make-spk.sh 1.0.11 [outdir]
#   NZBFAST_PAYLOAD_DIR=<dir> packaging/synology/make-spk.sh 1.0.11 [outdir]
#
# The shipped package is built by provenance-release.yml's
# `linux-packages` job (the second form), and attested there; the first
# form is for rebuilding one from a published release by hand.
#
# Produces ONE package, nzbfast-<ver>-noarch.spk, carrying both the
# x86_64 and aarch64 binaries; scripts/postinst keeps the one this NAS can
# run and deletes the other.
#
# One file rather than one per architecture, for two reasons that both
# come back to not asking users questions they cannot answer:
#   - DSM's package-source protocol filters by arch on the SERVER (the
#     feed returns a different package list per arch and carries no arch
#     field for the client to filter on), so a static host like GitHub
#     Pages cannot serve a per-arch feed from one URL. noarch means one
#     URL works for every model.
#   - Nobody downloading a .spk by hand has to know whether their NAS is
#     Intel or ARM.
# The cost is one unused binary inside the download, which postinst then
# removes from disk.
#
# Why a native package and not a container: DSM's Package Center is where
# most Synology owners install things, and a package can claim its own
# port, make its own folders and register its own service, so install is
# one click instead of a compose file and a wizard full of mount points.
#
# DSM 7 does NOT sign third-party packages - the codesign mechanism was
# removed, and with it DSM 6's "trust level" setting. Users get one
# unavoidable "not verified by Synology" prompt and that is the whole
# friction. There is no certificate to buy and nothing to configure here.
set -eu

VER="${1:?usage: make-spk.sh <version> [outdir] [port]}"
OUTDIR="${2:-dist}"
# The port is baked in at build time because DSM reads `adminport` out of
# INFO at install and cannot be told a different one later - so Package
# Center's Open button would point at the wrong place if postinst picked a
# port dynamically. 6789 is right for essentially everyone; a different
# value exists so a second instance can be built for testing alongside a
# running one.
PORT="${3:-6789}"
REL="https://github.com/nzbfast/nzbfast/releases/download/v${VER}"
SELF="$(cd "$(dirname "$0")" && pwd)"
SKEL="$SELF/spk"

if command -v sha256sum >/dev/null 2>&1; then SHA256C="sha256sum -c -"
else SHA256C="shasum -a 256 -c -"; fi

# Owner metadata, in whichever spelling this tar takes. bsdtar (the Mac,
# FreeBSD) zeroes with --uid/--gid/--uname/--gname; GNU tar (a Linux
# runner, where provenance-release.yml builds the shipped package) rejects
# those outright and writes no names at all under --numeric-owner. Both
# leave uid/gid 0 and empty name strings, which is what
# check-archive-identity.py's STRICT .spk arm demands. A function, not a
# variable: POSIX sh cannot carry the empty-string arguments in one.
if tar --version 2>&1 | head -1 | grep -qi bsdtar; then
    owner_tar() { tar --uid 0 --gid 0 --uname "" --gname "" "$@"; }
else
    owner_tar() { tar --owner=0 --group=0 --numeric-owner "$@"; }
fi

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

# Fetch + verify the released linux binaries. Each archive is checked
# against its OWN checksum line and that line has to exist, so a partial
# SHA256SUMS.txt cannot let an unverified binary into a package.
#
# NZBFAST_PAYLOAD_DIR is the other source, and the one a release uses
# since 23 Oct 2026: provenance-release.yml's `linux-packages` job builds
# this package on a runner, in the same run that builds and attests the
# two linux tarballs, before the release is public - so there is no
# release page to curl yet. The directory holds the same three files
# under the same names (the job writes SHA256SUMS.txt over the attested
# tarballs it took), and every check below runs unchanged. It is the
# same bytes the release page then carries, under the one name each, so
# the rule above - only bytes a published checksum covers - still holds.
if [ -n "${NZBFAST_PAYLOAD_DIR:-}" ]; then
    for f in "nzbfast-$VER-linux-x64.tar.gz" "nzbfast-$VER-linux-arm64.tar.gz" SHA256SUMS.txt; do
        cp "$NZBFAST_PAYLOAD_DIR/$f" "$DIR/$f"
    done
else
    for a in linux-x64 linux-arm64; do
        curl -fsSL -o "$DIR/nzbfast-$VER-$a.tar.gz" "$REL/nzbfast-$VER-$a.tar.gz"
    done
    curl -fsSL -o "$DIR/SHA256SUMS.txt" "$REL/SHA256SUMS.txt"
fi
for a in linux-x64 linux-arm64; do
    art="nzbfast-$VER-$a.tar.gz"
    n=$(grep -c "[ *]$art\$" "$DIR/SHA256SUMS.txt" || true)
    if [ "$n" != "1" ]; then
        echo "✗ SHA256SUMS.txt has $n checksum lines for $art (need exactly 1)" >&2
        exit 1
    fi
    (cd "$DIR" && grep "[ *]$art\$" SHA256SUMS.txt | $SHA256C)
done

build_spk() {
    work="$DIR/build"
    rm -rf "$work"
    mkdir -p "$work/package/bin"

    # linux-x64 -> x86_64, linux-arm64 -> aarch64. These are the names
    # postinst looks for; they are not our release-asset names.
    for pair in "linux-x64 x86_64" "linux-arm64 aarch64"; do
        asset=${pair% *}; arch=${pair#* }
        tar xzf "$DIR/nzbfast-$VER-$asset.tar.gz" -C "$DIR" \
            "nzbfast-$VER-$asset/nzbfast"
        cp "$DIR/nzbfast-$VER-$asset/nzbfast" "$work/package/bin/nzbfast-$arch"
        chmod 755 "$work/package/bin/nzbfast-$arch"
    done

    cp -R "$SKEL/conf" "$SKEL/scripts" "$work/"
    cp "$SELF/PACKAGE_ICON.PNG" "$SELF/PACKAGE_ICON_256.PNG" "$work/"
    chmod 755 "$work/scripts/"*

    # Bake the port in. Anything still holding the placeholder afterwards
    # is a file someone added without wiring it up, so fail loudly rather
    # than shipping a package with "@@PORT@@" in its firewall rule.
    sed "s/@@PORT@@/$PORT/g" "$work/scripts/postinst" > "$work/scripts/postinst.tmp"
    mv "$work/scripts/postinst.tmp" "$work/scripts/postinst"
    chmod 755 "$work/scripts/"*
    if grep -rl "@@PORT@@" "$work" 2>/dev/null | grep -q .; then
        echo "✗ unsubstituted @@PORT@@ left in:" >&2
        grep -rl "@@PORT@@" "$work" >&2
        exit 1
    fi

    cat > "$work/INFO" <<EOF
package="nzbfast"
version="$VER"
os_min_ver="7.0-40000"
description="Fast Usenet (NZB) downloader with a web dashboard and a SABnzbd- and NZBGet-compatible API. PAR2 repair and RAR extraction are native."
displayname="nzbfast"
arch="noarch"
maintainer="nzbfast"
maintainer_url="https://github.com/nzbfast/nzbfast"
distributor="nzbfast"
distributor_url="https://github.com/nzbfast/nzbfast"
support_url="https://github.com/nzbfast/nzbfast/issues"
thirdparty="yes"
silent_install="yes"
silent_uninstall="yes"
silent_upgrade="yes"
startable="yes"
adminport="$PORT"
adminprotocol="http"
EOF

    # package.tgz holds the payload CONTENTS, so bin/nzbfast lands at
    # /var/packages/nzbfast/target/bin/nzbfast - the path the systemd unit
    # execs. Tarring the wrapping `package` directory instead would bury
    # it one level deeper and the service would not start.
    #
    # The owner metadata has to be zeroed HERE too, not just on the outer
    # .spk. tar writes the building user's name into every entry, and the
    # inner archive is where it hides: zeroing only the outer tar leaves a
    # perfectly clean-looking package whose payload still names someone.
    (cd "$work/package" && owner_tar --format=ustar -czf "$work/package.tgz" .)
    rm -rf "$work/package"

    # The .spk itself is a PLAIN tar, not compressed. Owner metadata is
    # zeroed for the same reason release tarballs are: tar would otherwise
    # write the building user's name into every entry.
    # A non-default port means this is a test build, so say so in the
    # filename. The shipped artifact must never be ambiguous about which
    # port it claims, and these do get passed around by hand.
    name="nzbfast-$VER-noarch"
    [ "$PORT" = "6789" ] || name="$name-port$PORT"
    (cd "$work" && owner_tar --format=ustar -cf "$OUTDIR/$name.spk" \
        INFO package.tgz conf scripts PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG)
    echo "built $OUTDIR/$name.spk (port $PORT)"
}

build_spk

echo
echo "install: Package Center → Manual Install → nzbfast-$VER-noarch.spk,"
echo "         or add the package source and install from Community."
