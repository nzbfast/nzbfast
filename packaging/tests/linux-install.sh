#!/bin/sh
# Install the .deb and the .rpm for real, in systemd containers, and put
# them through an upgrade.
#
# packaging-tests-roster: installs the .deb and .rpm for real and needs
# docker. This is the one that READ as wired for as long as anyone looked,
# because pr-check.yml names it in a COMMENT. See the roster of deliberate
# exclusions in size-gate.yml's `packaging-gates` job.
#
# This is the test behind the claim in packaging/linux/README.md that an
# upgrade keeps your settings. It is not a mock: dpkg and rpm do the
# install, systemd runs the unit, the daemon serves its API, a setting is
# written THROUGH the daemon, and only then does the upgrade happen.
#
#   packaging/tests/linux-install.sh              # both families
#   packaging/tests/linux-install.sh deb          # one
#
# Needs: a LINUX host with docker (the containers run systemd as PID 1,
# which needs --privileged, so this does not run on the release Mac), and
# the two static musl binaries already built:
#
#   cargo zigbuild --release -p nzbfast \
#     --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl
#
# amd64 only: the packages for arm64 are built and structurally checked by
# packaging/linux/make-packages.sh, and smoke-tested under emulation
# (`docker run --platform linux/arm64 ... dpkg -i`), but systemd as PID 1
# under qemu-user is not a test anyone should trust.
set -eu

cd "$(dirname "$0")/../.."
HERE=packaging/tests/linux-install
OUT=$PWD/packaging/linux/out
FAMILIES=${1:-deb rpm}

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

# Build the packages in a container too, so the only thing this script
# needs from the host is docker - no dpkg-dev or rpm on the box itself.
echo "== building beta1 and beta2 packages =="
BUILDER=nzbfast-pkg-builder
docker build -q -t "$BUILDER" - >/dev/null <<'DOCKERFILE'
FROM debian:bookworm
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
        dpkg-dev rpm file && rm -rf /var/lib/apt/lists/*
DOCKERFILE
for beta in 1 2; do
    docker run --rm -v "$PWD:/w" -w /w -e NZBFAST_PKG_BETA=$beta "$BUILDER" \
        packaging/linux/make-packages.sh --arch amd64 --out /w/packaging/linux/out >/dev/null
done
ls -1 "$OUT"

VER=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/nzbfast/Cargo.toml | head -1)
rc=0
for fam in $FAMILIES; do
    case "$fam" in
        deb) img=nzbfast-test-deb; dockerfile=$HERE/Dockerfile.debian
             a="/o/nzbfast_${VER}-0beta1_amd64.deb"
             b="/o/nzbfast_${VER}-0beta2_amd64.deb" ;;
        rpm) img=nzbfast-test-rpm; dockerfile=$HERE/Dockerfile.fedora
             a="/o/nzbfast-${VER}-0.beta1.x86_64.rpm"
             b="/o/nzbfast-${VER}-0.beta2.x86_64.rpm" ;;
        *) echo "unknown family: $fam (use deb or rpm)" >&2; exit 1 ;;
    esac
    echo
    echo "== $fam: building the systemd image =="
    docker build -q -t "$img" -f "$dockerfile" "$HERE" >/dev/null
    name="nzbfast-test-$fam-$$"
    docker rm -f "$name" >/dev/null 2>&1 || true
    # --privileged and the two tmpfs mounts are what systemd needs as PID
    # 1 in a container. Nothing is published to the host: the checks curl
    # the daemon from inside.
    docker run -d --name "$name" --privileged --tmpfs /run --tmpfs /run/lock \
        -v "$OUT:/o:ro" -v "$PWD/$HERE/checks.sh:/checks.sh:ro" "$img" >/dev/null
    i=0
    while [ $i -lt 30 ]; do
        [ "$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)" = running ] && break
        i=$((i + 1)); sleep 1
    done
    if docker exec "$name" /checks.sh "$fam" "$a" "$b"; then
        echo "== $fam: PASSED =="
    else
        echo "== $fam: FAILED ==" >&2
        rc=1
    fi
    docker rm -f "$name" >/dev/null
done
exit $rc
